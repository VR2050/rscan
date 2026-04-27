package io.reactivex.internal.fuseable;

import org.reactivestreams.Publisher;

/* JADX INFO: loaded from: classes3.dex */
public interface HasUpstreamPublisher<T> {
    Publisher<T> source();
}
