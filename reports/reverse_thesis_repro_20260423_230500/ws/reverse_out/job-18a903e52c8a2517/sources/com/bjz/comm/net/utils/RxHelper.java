package com.bjz.comm.net.utils;

import android.text.TextUtils;
import android.util.Log;
import com.android.tools.r8.annotations.SynthesizedClassMap;
import com.bjz.comm.net.BuildVars;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.BResponseNoData;
import com.bjz.comm.net.exception.ApiException;
import com.bjz.comm.net.exception.KeyNotValidThrowable;
import com.google.gson.JsonSyntaxException;
import io.reactivex.Observable;
import io.reactivex.ObservableSource;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.disposables.CompositeDisposable;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Action;
import io.reactivex.functions.Consumer;
import io.reactivex.functions.Function;
import io.reactivex.schedulers.Schedulers;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.concurrent.Callable;

/* JADX INFO: loaded from: classes4.dex */
@SynthesizedClassMap({$$Lambda$RxHelper$9Fpeevt_AEBx4Inh91E9OBxsjI.class, $$Lambda$RxHelper$L4h52ayeOJhEGoRaDCAiLt5cFSM.class, $$Lambda$RxHelper$TCkWU_RHRI6J4gvtltD_EDaVs0.class, $$Lambda$RxHelper$WbTnyinO42jR_Y9WXZuZpFouOpU.class, $$Lambda$RxHelper$YXMpiTgUkxP3dG6KMw4qhqDLQu0.class, $$Lambda$RxHelper$dShrgWvM2sG2Y2G_WXd9Fe4Io9I.class})
public class RxHelper {
    private static String TAG = RxHelper.class.getSimpleName();
    private HashMap<String, CompositeDisposable> mTaskDisposable;

    /* synthetic */ RxHelper(AnonymousClass1 x0) {
        this();
    }

    private static class RxHelperHolder {
        private static RxHelper instance = new RxHelper(null);

        private RxHelperHolder() {
        }
    }

    private RxHelper() {
        this.mTaskDisposable = new HashMap<>();
    }

    public static RxHelper getInstance() {
        return RxHelperHolder.instance;
    }

    private void addTaskDisposable(String tag, Disposable disposable) {
        if (this.mTaskDisposable.get(tag) != null) {
            this.mTaskDisposable.get(tag).add(disposable);
            return;
        }
        CompositeDisposable compositeDisposable = new CompositeDisposable();
        compositeDisposable.add(disposable);
        this.mTaskDisposable.put(tag, compositeDisposable);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public <T> void sendSimpleRequest(final String tag, Observable<T> observable, Consumer<T> consumer, Consumer<Throwable> onError) {
        addTaskDisposable(tag, observable.subscribeOn(Schedulers.io()).observeOn(AndroidSchedulers.mainThread()).doOnComplete(new Action() { // from class: com.bjz.comm.net.utils.-$$Lambda$RxHelper$dShrgWvM2sG2Y2G_WXd9Fe4Io9I
            @Override // io.reactivex.functions.Action
            public final void run() throws Exception {
                this.f$0.lambda$sendSimpleRequest$0$RxHelper(tag);
            }
        }).subscribe(consumer, onError));
    }

    public <R> void sendRequest(final String tag, Observable<BResponse<R>> observable, Consumer<BResponse<R>> onNext, Consumer<Throwable> onError) {
        Disposable disposable = send(observable).subscribeOn(Schedulers.io()).observeOn(AndroidSchedulers.mainThread()).doOnComplete(new Action() { // from class: com.bjz.comm.net.utils.-$$Lambda$RxHelper$9Fpee-vt_AEBx4Inh91E9OBxsjI
            @Override // io.reactivex.functions.Action
            public final void run() throws Exception {
                this.f$0.lambda$sendRequest$1$RxHelper(tag);
            }
        }).subscribe(onNext, onError);
        addTaskDisposable(tag, disposable);
    }

    private <R> Observable send(final Observable<R> observable) {
        return Observable.defer(new Callable() { // from class: com.bjz.comm.net.utils.-$$Lambda$RxHelper$YXMpiTgUkxP3dG6KMw4qhqDLQu0
            @Override // java.util.concurrent.Callable
            public final Object call() {
                return Observable.just(HttpUtils.getInstance().getAuthorization());
            }
        }).flatMap(new Function() { // from class: com.bjz.comm.net.utils.-$$Lambda$RxHelper$L4h52ayeOJhEGoRaDCAiLt5cFSM
            @Override // io.reactivex.functions.Function
            public final Object apply(Object obj) {
                return RxHelper.lambda$send$3(observable, (String) obj);
            }
        }).retryWhen(new AnonymousClass1());
    }

    static /* synthetic */ ObservableSource lambda$send$3(Observable observable, String key) throws Exception {
        if (TextUtils.isEmpty(key)) {
            if (BuildVars.DEBUG_VERSION) {
                Log.e(TAG, "TokenRequest = null");
            }
            return Observable.error(new KeyNotValidThrowable());
        }
        if (BuildVars.DEBUG_VERSION) {
            Log.e(TAG, "TokenRequest = " + key);
        }
        return observable;
    }

    /* JADX INFO: renamed from: com.bjz.comm.net.utils.RxHelper$1, reason: invalid class name */
    @SynthesizedClassMap({$$Lambda$RxHelper$1$TnzVRd1bFX7YUmmhsyaFgAlGrg.class})
    class AnonymousClass1 implements Function<Observable<? extends Throwable>, ObservableSource<?>> {
        private int retryCount = 0;

        AnonymousClass1() {
        }

        @Override // io.reactivex.functions.Function
        public ObservableSource<?> apply(Observable<? extends Throwable> throwableObservable) throws Exception {
            return throwableObservable.flatMap(new Function() { // from class: com.bjz.comm.net.utils.-$$Lambda$RxHelper$1$TnzVRd1bFX7YUmmhs-yaFgAlGrg
                @Override // io.reactivex.functions.Function
                public final Object apply(Object obj) {
                    return this.f$0.lambda$apply$0$RxHelper$1((Throwable) obj);
                }
            });
        }

        public /* synthetic */ ObservableSource lambda$apply$0$RxHelper$1(Throwable throwable) throws Exception {
            if (BuildVars.DEBUG_VERSION) {
                Log.e(RxHelper.TAG, "TokenRequest retryCount = " + this.retryCount);
            }
            if (throwable instanceof KeyNotValidThrowable) {
                if (BuildVars.DEBUG_VERSION) {
                    Log.e(RxHelper.TAG, "TokenRequest KeyNotValidThrowable");
                }
                int i = this.retryCount;
                if (i > 0) {
                    return Observable.error(throwable);
                }
                this.retryCount = i + 1;
                return TokenLoader.getInstance().getNetTokenLocked();
            }
            if (throwable instanceof ApiException) {
                if (BuildVars.DEBUG_VERSION) {
                    Log.e(RxHelper.TAG, "TokenRequest ApiException");
                }
                ApiException apiException = (ApiException) throwable;
                if (apiException.getCode() == 400) {
                    int i2 = this.retryCount;
                    if (i2 > 0) {
                        return Observable.error(throwable);
                    }
                    this.retryCount = i2 + 1;
                    return TokenLoader.getInstance().getNetTokenLocked();
                }
            }
            return Observable.error(throwable);
        }
    }

    public void sendRequestNoData(final String tag, Observable<BResponseNoData> observable, Consumer<BResponseNoData> onNext, Consumer<Throwable> onError) {
        Disposable disposable = send(observable).subscribeOn(Schedulers.io()).observeOn(AndroidSchedulers.mainThread()).doOnComplete(new Action() { // from class: com.bjz.comm.net.utils.-$$Lambda$RxHelper$TCkWU_RHRI6J4gvtltD_EDaVs-0
            @Override // io.reactivex.functions.Action
            public final void run() throws Exception {
                this.f$0.lambda$sendRequestNoData$4$RxHelper(tag);
            }
        }).subscribe(onNext, onError);
        addTaskDisposable(tag, disposable);
    }

    public <R> void sendCommRequest(final String tag, Observable<R> observable, Consumer<R> onNext, Consumer<Throwable> onError) {
        Disposable disposable = send(observable).subscribeOn(Schedulers.io()).observeOn(AndroidSchedulers.mainThread()).doOnComplete(new Action() { // from class: com.bjz.comm.net.utils.-$$Lambda$RxHelper$WbTnyinO42jR_Y9WXZuZpFouOpU
            @Override // io.reactivex.functions.Action
            public final void run() throws Exception {
                this.f$0.lambda$sendCommRequest$5$RxHelper(tag);
            }
        }).subscribe(onNext, onError);
        addTaskDisposable(tag, disposable);
    }

    /* JADX INFO: renamed from: unSubscribeTask, reason: merged with bridge method [inline-methods] and merged with bridge method [inline-methods] and merged with bridge method [inline-methods] and merged with bridge method [inline-methods] */
    public void lambda$sendSimpleRequest$0$RxHelper(String tag) {
        Disposable dis = this.mTaskDisposable.get(tag);
        if (dis != null) {
            if (!dis.isDisposed()) {
                dis.dispose();
            }
            this.mTaskDisposable.remove(tag);
        }
    }

    public String getErrorInfo(Throwable throwable) {
        if (BuildVars.DEBUG_VERSION) {
            Log.e("TAG", "" + throwable.getMessage());
        }
        if (throwable instanceof SocketTimeoutException) {
            return "请求超时";
        }
        if (throwable instanceof UnknownHostException) {
            return "网络异常";
        }
        if (throwable instanceof IOException) {
            return "服务器异常";
        }
        if (throwable instanceof JsonSyntaxException) {
            return "返回数据异常";
        }
        return "请求失败";
    }
}
