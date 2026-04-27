package io.reactivex;

/* JADX INFO: loaded from: classes3.dex */
public interface ObservableTransformer<Upstream, Downstream> {
    ObservableSource<Downstream> apply(Observable<Upstream> observable);
}
