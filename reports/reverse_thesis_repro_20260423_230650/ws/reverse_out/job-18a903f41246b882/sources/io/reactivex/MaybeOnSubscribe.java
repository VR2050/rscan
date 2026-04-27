package io.reactivex;

/* JADX INFO: loaded from: classes3.dex */
public interface MaybeOnSubscribe<T> {
    void subscribe(MaybeEmitter<T> maybeEmitter) throws Exception;
}
