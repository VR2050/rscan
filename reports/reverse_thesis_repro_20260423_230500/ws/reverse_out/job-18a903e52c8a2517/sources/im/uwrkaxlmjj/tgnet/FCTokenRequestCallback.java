package im.uwrkaxlmjj.tgnet;

import android.text.TextUtils;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.TokenRequest;
import com.bjz.comm.net.factory.ApiFactory;
import com.bjz.comm.net.listener.GetHttpTokenCallBack;
import com.google.gson.Gson;
import com.socks.library.KLog;
import im.uwrkaxlmjj.javaBean.AllTokenResponse;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.FCTokenRequestCallback;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCBasic;
import io.reactivex.Observable;
import io.reactivex.ObservableEmitter;
import io.reactivex.ObservableOnSubscribe;
import io.reactivex.ObservableSource;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Consumer;
import io.reactivex.functions.Function;
import io.reactivex.schedulers.Schedulers;
import java.util.concurrent.TimeUnit;
import org.json.JSONException;

/* JADX INFO: loaded from: classes2.dex */
public class FCTokenRequestCallback implements GetHttpTokenCallBack {
    private static final String TAG = FCTokenRequestCallback.class.getSimpleName();

    /* JADX INFO: renamed from: im, reason: collision with root package name */
    private boolean f27im = true;
    private Disposable disposable = null;

    public static FCTokenRequestCallback getInstance() {
        return Holder.INSTANCE;
    }

    private static class Holder {
        private static final FCTokenRequestCallback INSTANCE = new FCTokenRequestCallback();

        private Holder() {
        }
    }

    @Override // com.bjz.comm.net.listener.GetHttpTokenCallBack
    public void requestToken(final ObservableEmitter<String> ef) throws JSONException {
        KLog.e("TAG", "获取Token start");
        if (this.f27im) {
            Disposable disposable = this.disposable;
            if (disposable != null && !disposable.isDisposed()) {
                this.disposable.dispose();
                this.disposable = null;
            }
            this.disposable = Observable.create(new AnonymousClass2()).timeout(5L, TimeUnit.SECONDS).retryWhen(new Function<Observable<Throwable>, ObservableSource<String>>() { // from class: im.uwrkaxlmjj.tgnet.FCTokenRequestCallback.1
                private int retryCount = 0;

                static /* synthetic */ int access$108(AnonymousClass1 x0) {
                    int i = x0.retryCount;
                    x0.retryCount = i + 1;
                    return i;
                }

                @Override // io.reactivex.functions.Function
                public ObservableSource<String> apply(Observable<Throwable> throwableObservable) throws Exception {
                    return throwableObservable.flatMap(new Function<Throwable, ObservableSource<String>>() { // from class: im.uwrkaxlmjj.tgnet.FCTokenRequestCallback.1.1
                        @Override // io.reactivex.functions.Function
                        public ObservableSource<String> apply(Throwable throwable) throws Exception {
                            AnonymousClass1.access$108(AnonymousClass1.this);
                            KLog.e(FCTokenRequestCallback.TAG, "获取朋友圈Token retryThrowable = " + throwable.getMessage());
                            KLog.e(FCTokenRequestCallback.TAG, "获取朋友圈Token retryCount = " + AnonymousClass1.this.retryCount);
                            if (AnonymousClass1.this.retryCount != 3) {
                                if (AnonymousClass1.this.retryCount > 3) {
                                    return Observable.error(throwable);
                                }
                                return Observable.just("");
                            }
                            return Observable.just("");
                        }
                    });
                }
            }).subscribeOn(Schedulers.io()).subscribe(new Consumer() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$FCTokenRequestCallback$JTzTmaY_yE8CHaG_LLYEUDbDIw8
                @Override // io.reactivex.functions.Consumer
                public final void accept(Object obj) throws Exception {
                    this.f$0.lambda$requestToken$0$FCTokenRequestCallback(ef, (String) obj);
                }
            }, new Consumer() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$FCTokenRequestCallback$YWbsFDMvWw0igGeO05q9zAfgjaA
                @Override // io.reactivex.functions.Consumer
                public final void accept(Object obj) throws Exception {
                    this.f$0.lambda$requestToken$1$FCTokenRequestCallback(ef, (Throwable) obj);
                }
            });
            return;
        }
        int clientUserId = UserConfig.getInstance(UserConfig.selectedAccount).getClientUserId();
        Observable<BResponse<TokenRequest>> token = ApiFactory.getInstance().getApiMomentForum().getToken(clientUserId);
        token.subscribeOn(Schedulers.io()).subscribe(new Consumer() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$FCTokenRequestCallback$5Ih5xg6kkpAOnoXE9mnXWWx5IvE
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                FCTokenRequestCallback.lambda$requestToken$2(ef, (BResponse) obj);
            }
        }, new Consumer() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$FCTokenRequestCallback$B_LvWscB8MvcMKCBnn7spsyZfJs
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) {
                ef.onError((Throwable) obj);
            }
        });
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.tgnet.FCTokenRequestCallback$2, reason: invalid class name */
    class AnonymousClass2 implements ObservableOnSubscribe<String> {
        AnonymousClass2() {
        }

        @Override // io.reactivex.ObservableOnSubscribe
        public void subscribe(final ObservableEmitter<String> e) throws Exception {
            TLRPCBasic.TL_GetToken req = new TLRPCBasic.TL_GetToken();
            req.friendCircle = true;
            AccountInstance instance = AccountInstance.getInstance(UserConfig.selectedAccount);
            instance.getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$FCTokenRequestCallback$2$7QcWUhIwvn7Zmwj6kX6FuqR9PMQ
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) throws JSONException {
                    FCTokenRequestCallback.AnonymousClass2.lambda$subscribe$0(e, tLObject, tL_error);
                }
            });
        }

        static /* synthetic */ void lambda$subscribe$0(ObservableEmitter e, TLObject response, TLRPC.TL_error error) throws JSONException {
            if (!(response instanceof TLRPCBasic.TL_AllToken)) {
                KLog.e(FCTokenRequestCallback.TAG, "获取朋友圈Token error == " + error.text);
                return;
            }
            TLRPCBasic.TL_AllToken tl_allToken = (TLRPCBasic.TL_AllToken) response;
            TLRPC.TL_dataJSON tokens = tl_allToken.tokens;
            if (tokens == null) {
                KLog.e(FCTokenRequestCallback.TAG, "获取朋友圈Token error == " + error.text);
                e.onError(new Throwable(error.text != null ? error.text : "获取Token失败"));
                return;
            }
            String data = tokens.data;
            if (TextUtils.isEmpty(data)) {
                KLog.e(FCTokenRequestCallback.TAG, "获取朋友圈Token data == null ");
                e.onError(new Throwable("获取Token失败"));
                return;
            }
            try {
                AllTokenResponse tokenResponse = (AllTokenResponse) new Gson().fromJson(data, AllTokenResponse.class);
                if (tokenResponse != null) {
                    String momenttoken = tokenResponse.getMomenttoken();
                    KLog.e(FCTokenRequestCallback.TAG, "获取朋友圈Token == " + momenttoken);
                    e.onNext(momenttoken);
                }
            } catch (Exception exception) {
                KLog.e(FCTokenRequestCallback.TAG, "获取朋友圈Token error == " + exception.getMessage());
                e.onError(exception);
            }
        }
    }

    public /* synthetic */ void lambda$requestToken$0$FCTokenRequestCallback(ObservableEmitter ef, String o) throws Exception {
        Disposable disposable = this.disposable;
        if (disposable != null && !disposable.isDisposed()) {
            this.disposable.dispose();
            this.disposable = null;
        }
        ef.onNext(o);
    }

    public /* synthetic */ void lambda$requestToken$1$FCTokenRequestCallback(ObservableEmitter ef, Throwable throwable) throws Exception {
        Disposable disposable = this.disposable;
        if (disposable != null && !disposable.isDisposed()) {
            this.disposable.dispose();
            this.disposable = null;
        }
        ef.onError(throwable);
    }

    /* JADX WARN: Multi-variable type inference failed */
    static /* synthetic */ void lambda$requestToken$2(ObservableEmitter ef, BResponse tokenRequestBResponse) throws Exception {
        if (tokenRequestBResponse.isState() && tokenRequestBResponse.Data != 0) {
            ef.onNext(((TokenRequest) tokenRequestBResponse.Data).getToken());
        } else {
            ef.onError(new Throwable("获取token失败"));
        }
    }
}
