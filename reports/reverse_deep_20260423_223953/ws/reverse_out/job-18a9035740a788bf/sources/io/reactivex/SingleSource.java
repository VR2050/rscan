package io.reactivex;

/* JADX INFO: loaded from: classes3.dex */
public interface SingleSource<T> {
    void subscribe(SingleObserver<? super T> singleObserver);
}
