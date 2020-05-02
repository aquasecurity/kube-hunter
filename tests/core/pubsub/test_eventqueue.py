import functools
import pytest

from queue import Empty as QueueEmpty
from typing import Type
from kube_hunter.conf import Config, set_config
from kube_hunter.core.pubsub.eventqueue import EventQueue, EventRegistry
from kube_hunter.core.pubsub.subscription import Event, EventFilter, Subscriber, Target, subscribe, subscribe_once

set_config(Config())


class SomeEvent(Event):
    pass


class SomeEventSubclass(SomeEvent):
    pass


class AnotherEvent(Event):
    pass


@pytest.fixture(params=[Subscriber, EventFilter], scope="function")
def subscriber_type(request):
    return request.param


@pytest.fixture(scope="function")
def queue():
    return EventQueue()


@pytest.fixture(scope="function")
def registry():
    return EventRegistry()


class TestEventRegistry:
    def test_get_subscribers_no_subscriptions(self, registry):
        assert not registry.get_subscribers(SomeEvent())

    def test_get_subscribers_one_event_single_subscriber(self, registry):
        class SomeSubscriber(Subscriber):
            pass

        expected = [SomeSubscriber]
        registry.add(SomeSubscriber, Target(SomeEvent))
        actual = registry.get_subscribers(SomeEvent())

        assert expected == actual

    def test_get_subscribers_single_event_multiple_subscribers(self, registry):
        class SomeSubscriber(Subscriber):
            pass

        class AnotherSubscriber(Subscriber):
            pass

        expected = [SomeSubscriber, AnotherSubscriber]
        registry.add(SomeSubscriber, Target(SomeEvent))
        registry.add(AnotherSubscriber, Target(SomeEvent))
        actual = registry.get_subscribers(SomeEvent())

        assert expected == actual

    def test_get_subscribers_multiple_events_single_subscriber(self, registry):
        class SomeSubscriber(Subscriber):
            pass

        expected = [SomeSubscriber]
        registry.add(SomeSubscriber, Target(SomeEvent))
        registry.add(SomeSubscriber, Target(AnotherEvent))

        assert expected == registry.get_subscribers(SomeEvent())
        assert expected == registry.get_subscribers(AnotherEvent())

    def test_get_subscribers_same_event_twice(self, registry):
        class SomeSubscriber(Subscriber):
            pass

        expected = [SomeSubscriber]
        registry.add(SomeSubscriber, Target(SomeEvent))
        registry.add(SomeSubscriber, Target(SomeEvent))
        actual = registry.get_subscribers(SomeEvent())

        assert expected == actual

    def test_get_subscribers_subclass_event(self, registry):
        class SomeSubscriber(Subscriber):
            pass

        expected = [SomeSubscriber]
        registry.add(SomeSubscriber, Target(SomeEventSubclass))
        actual = registry.get_subscribers(SomeEvent())

        assert expected == actual

    def test_get_subscribers_with_predicate(self, registry, subscriber_type):
        class SomeSubscriber(subscriber_type):
            pass

        registry.add(SomeSubscriber, Target(SomeEvent, predicate=lambda _: False))

        assert not registry.get_subscribers(SomeEvent())


class TestEventQueue:
    def is_subscribed(self, queue: EventQueue, subscriber: Type[Subscriber], subject: Type[Event]):
        registry = queue._event_registry(subscriber)
        return subject in (target.subject for target in registry._records[subscriber])

    def test_started(self):
        event_queue = EventQueue(2)
        event_queue.start()

        assert event_queue.running
        assert all(t.is_alive() for t in event_queue.workers)

    def test_register_no_subscriptions(self, queue, subscriber_type):
        class SomeSubscriber(subscriber_type):
            pass

        with pytest.raises(ValueError, match="subscriber does not have subscriptions"):
            queue.register(SomeSubscriber)

    def test_register_invalid_type(self, queue):
        class NotSubscriber:
            pass

        with pytest.raises(ValueError, match="subscriber does not have subscriptions"):
            queue.register(NotSubscriber)

    def test_register_got_registered(self, queue, subscriber_type):
        @subscribe(SomeEvent)
        class SomeSubscriber(subscriber_type):
            pass

        queue.register(SomeSubscriber)

        assert self.is_subscribed(queue, SomeSubscriber, SomeEvent)

    def test_register_multiple_events(self, queue, subscriber_type):
        @subscribe(SomeEvent)
        @subscribe(AnotherEvent)
        class SomeSubscriber(subscriber_type):
            pass

        queue.register(SomeSubscriber)

        assert self.is_subscribed(queue, SomeSubscriber, SomeEvent)
        assert self.is_subscribed(queue, SomeSubscriber, SomeEvent)

    def test_unregister_got_unregistered(self, queue, subscriber_type):
        @subscribe(SomeEvent)
        class SomeSubscriber(subscriber_type):
            pass

        queue.register(SomeSubscriber)
        queue.unregister(SomeSubscriber)

        assert not self.is_subscribed(queue, SomeSubscriber, SomeEvent)

    def test_unregister_multiple_events(self, queue, subscriber_type):
        @subscribe(SomeEvent)
        @subscribe(AnotherEvent)
        class SomeSubscriber(subscriber_type):
            pass

        queue.register(SomeSubscriber)
        queue.unregister(SomeSubscriber)

        assert not self.is_subscribed(queue, SomeSubscriber, SomeEvent)
        assert not self.is_subscribed(queue, SomeSubscriber, SomeEvent)

    def test_unregister_no_subscriptions(self, queue, subscriber_type):
        class SomeSubscriber(subscriber_type):
            pass

        with pytest.raises(ValueError, match="subscriber does not have subscriptions"):
            queue.unregister(SomeSubscriber)

    def test_unregister_not_exists(self, queue, subscriber_type):
        @subscribe(SomeEvent)
        class SomeSubscriber(subscriber_type):
            pass

        with pytest.raises(ValueError, match="subscriber is not subscribed"):
            queue.unregister(SomeSubscriber)

    def test_register_once_got_subscribed(self, queue, subscriber_type):
        @subscribe_once(SomeEvent)
        class SomeSubscriber(Subscriber):
            def execute(self):
                pass

        queue.register(SomeSubscriber)

        assert self.is_subscribed(queue, SomeSubscriber, SomeEvent)

    def test_register_once_got_unsubscribed(self, queue, subscriber_type):
        @subscribe_once(SomeEvent)
        class SomeSubscriber(subscriber_type):
            def execute(self):
                pass

        queue.register(SomeSubscriber)
        SomeSubscriber(SomeEvent()).execute()

        assert not self.is_subscribed(queue, SomeSubscriber, SomeEvent)

    def test_register_once_no_reunsubscribed(self, queue, subscriber_type):
        """test_register_once_no_reunsubscribed
        Check that it doesn't get re-unsubscribed and raises exception
        """

        @subscribe_once(SomeEvent)
        class SomeSubscriber(subscriber_type):
            def execute(self):
                pass

        queue.register(SomeSubscriber)
        SomeSubscriber(SomeEvent()).execute()
        SomeSubscriber(SomeEvent()).execute()

    def test_event_registry_for_subscriber(self, queue):
        class SomeSubscriber(Subscriber):
            pass

        registry = queue._event_registry(SomeSubscriber)

        assert registry is queue.hooks

    def test_event_registry_filter(self, queue):
        class SomeSubscriber(EventFilter):
            pass

        registry = queue._event_registry(SomeSubscriber)

        assert registry is queue.filters

    def test_apply_filters_no_filters(self, queue):
        expected = SomeEvent()
        actual = queue._apply_filters(expected)

        assert expected is actual

    def test_apply_filters_no_change(self, queue):
        @subscribe(SomeEvent)
        class NoChangeFilter(EventFilter):
            def execute(self):
                pass

        expected = SomeEvent()
        queue.register(NoChangeFilter)
        actual = queue._apply_filters(expected)

        assert expected is actual

    def test_apply_filters_predicate_filter(self, queue):
        @subscribe(SomeEvent, predicate=lambda _: False)
        class NotCalledFilter(EventFilter):
            def execute(self):
                self.event = None

        expected = SomeEvent()
        queue.register(NotCalledFilter)
        actual = queue._apply_filters(expected)

        assert expected is actual

    def test_apply_filters_drop_event(self, queue):
        @subscribe(SomeEvent)
        class NoChangeFilter(EventFilter):
            def execute(self):
                self.event = None

        queue.register(NoChangeFilter)

        assert not queue._apply_filters(SomeEvent())

    def test_apply_filters_change_event(self, queue):
        @subscribe(SomeEvent)
        class ChangeToAnotherEventFilter(EventFilter):
            def execute(self):
                self.event = AnotherEvent()

        queue.register(ChangeToAnotherEventFilter)
        actual = queue._apply_filters(SomeEvent())

        assert isinstance(actual, AnotherEvent)

    def test_apply_filters_multiple_filters(self, queue):
        @subscribe(SomeEvent)
        class AddSomeField(EventFilter):
            def execute(self):
                self.event.some_field = None

        @subscribe(SomeEvent)
        class AddAnotherField(EventFilter):
            def execute(self):
                self.event.another_field = None

        queue.register(AddSomeField)
        queue.register(AddAnotherField)
        event = queue._apply_filters(SomeEvent())

        assert hasattr(event, "some_field")
        assert hasattr(event, "another_field")

    def test_apply_filters_filter_raises_exception(self, queue):
        @subscribe(SomeEvent)
        class FailingFilter(EventFilter):
            def execute(self):
                raise NotImplementedError("failing filter")

        queue.register(FailingFilter)

        with pytest.raises(NotImplementedError, match="failing filter"):
            queue._apply_filters(SomeEvent())

    def test_publish_event_dropped_by_filter(self, queue):
        @subscribe(SomeEvent)
        class SomeSubscriber(Subscriber):
            def execute(self):
                pass

        @subscribe(SomeEvent)
        class DroppingFilter(EventFilter):
            def execute(self):
                self.event = None

        queue.register(SomeSubscriber)
        queue.register(DroppingFilter)
        queue.publish_event(SomeEvent())

        assert queue.queue.empty()

    def test_publish_event_single_subscriber(self, queue):
        @subscribe(SomeEvent)
        class SomeSubscriber(Subscriber):
            def execute(self):
                pass

        queue.register(SomeSubscriber)
        queue.publish_event(SomeEvent())
        published = queue.queue.get_nowait()

        assert published
        assert isinstance(published, SomeSubscriber)
        assert queue.queue.empty()

    def test_publish_event_multiple_subscribers(self, queue):
        @subscribe(SomeEvent)
        class SomeSubscriber(Subscriber):
            def execute(self):
                pass

        @subscribe(SomeEvent)
        class AnotherSubscriber(Subscriber):
            def execute(self):
                pass

        expected = set([SomeSubscriber, AnotherSubscriber])
        queue.register(SomeSubscriber)
        queue.register(AnotherSubscriber)
        queue.publish_event(SomeEvent())
        published_first = queue.queue.get_nowait()
        published_second = queue.queue.get_nowait()
        actual = set([type(published_first), type(published_second)])

        assert queue.queue.empty()
        assert expected == actual

    def test_publish_event_set_caller(self, queue):
        class FirstSubscriber(Subscriber):
            def execute(self):
                pass

        @subscribe(SomeEvent)
        class SecondSubscriber(Subscriber):
            def execute(self):
                pass

        first_event = SomeEvent()
        second_event = SomeEvent()
        queue.register(SecondSubscriber)
        queue.publish_event(second_event, caller=FirstSubscriber(first_event))
        published = queue.queue.get_nowait()

        assert published
        assert queue.queue.empty()
        assert published.event is second_event
        assert published.event.hunter is FirstSubscriber
        assert published.event.previous is first_event

    def test_publish_event_set_caller_after_filter_change(self, queue):
        class FirstSubscriber(Subscriber):
            def execute(self):
                pass

        @subscribe(SomeEvent)
        class SecondSubscriber(Subscriber):
            def execute(self):
                pass

        @subscribe(SomeEvent)
        class RecreateFilter(EventFilter):
            def execute(self):
                self.event = SomeEvent()

        first_event = SomeEvent()
        second_event = SomeEvent()
        queue.register(SecondSubscriber)
        queue.register(RecreateFilter)
        queue.publish_event(second_event, caller=FirstSubscriber(first_event))
        published = queue.queue.get_nowait()

        assert published
        assert queue.queue.empty()
        assert published.event.hunter is FirstSubscriber
        assert published.event.previous is first_event
        assert published.event is not second_event

    @pytest.mark.timeout(1)
    def test_worker_stops_not_running(self, queue):
        queue.running = False
        queue._worker()

    @pytest.mark.timeout(1)
    def test_worker_stops_after_iteration(self, queue):
        @functools.wraps(queue._worker_iteration)
        def stop_running(*args, **kwargs):
            queue.running = False
            stop_running.called = True

        queue._worker_iteration = stop_running
        queue.worker_poll_timeout = 0.1
        queue.queue.put(None)
        queue.running = True
        queue._worker()

        assert getattr(stop_running, "called", False)
        assert not queue.queue.unfinished_tasks

    @pytest.mark.timeout(1)
    def test_worker_times_out(self, queue):
        @functools.wraps(queue.queue.get)
        def stop_running(*args, **kwargs):
            queue.running = False
            stop_running.called = True
            raise QueueEmpty()

        queue.queue.get = stop_running
        queue.worker_poll_timeout = 0.1
        queue.running = True
        queue._worker()

        assert getattr(stop_running, "called", False)

    def test_worker_iteration_catch_exception(self, queue):
        class FailingSubscriber(Subscriber):
            def execute(self):
                raise NotImplementedError()

        queue._worker_iteration(FailingSubscriber(SomeEvent()))

    def test_worker_iteration_event_published(self, queue):
        @subscribe(SomeEvent)
        class PublishingSubscriber(Subscriber):
            def execute(self):
                yield AnotherEvent()

        @functools.wraps(queue.publish_event)
        def publish_mock(event, caller):
            assert not hasattr(publish_mock, "called_with")
            publish_mock.called_with = (event, caller)

        queue.publish_event = publish_mock
        subscriber = PublishingSubscriber(SomeEvent())
        queue._worker_iteration(subscriber)
        event, caller = publish_mock.called_with

        assert isinstance(event, AnotherEvent)
        assert caller is subscriber

    def test_finished_no_events_left(self, queue):
        assert queue.finished()

    def test_finished_events_left(self, queue):
        queue.queue.unfinished_tasks = 1
        assert not queue.finished()

    def test_stop_not_running(self, queue):
        with pytest.raises(AssertionError, match="not running"):
            queue.stop()

    @pytest.mark.timeout(1)
    def test_stop_no_wait(self, queue):
        queue.running = True
        queue.stop()

        assert not queue.running

    @pytest.mark.timeout(1)
    def test_stop_wait(self, queue):
        queue.running = True
        queue.stop(wait=True)

        assert not queue.running
