package com.jbzd.media.movecartoons.p396ui.mine;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.TokenBean;
import com.jbzd.media.movecartoons.bean.request.RequestSystemInfoBody;
import com.jbzd.media.movecartoons.bean.response.AppBean;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.HeadImageBean;
import com.jbzd.media.movecartoons.bean.response.PicVefBean;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.bean.response.system.SystemInfoBean;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import com.yalantis.ucrop.view.CropImageView;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.C0887j;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p006a.p007a.p008a.p017r.C0925i;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p379c.p380a.C3109w0;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.p383b2.InterfaceC3006b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u008e\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0010 \n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u0000 \u0083\u00012\u00020\u0001:\u0002\u0083\u0001B\b¢\u0006\u0005\b\u0082\u0001\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0006\u0010\u0004J\r\u0010\u0007\u001a\u00020\u0002¢\u0006\u0004\b\u0007\u0010\u0004J%\u0010\f\u001a\u00020\u00022\u0006\u0010\t\u001a\u00020\b2\u0006\u0010\n\u001a\u00020\b2\u0006\u0010\u000b\u001a\u00020\b¢\u0006\u0004\b\f\u0010\rJ\u001d\u0010\u000f\u001a\u00020\u00022\u0006\u0010\t\u001a\u00020\b2\u0006\u0010\u000e\u001a\u00020\b¢\u0006\u0004\b\u000f\u0010\u0010J\u001d\u0010\u0011\u001a\u00020\u00022\u0006\u0010\t\u001a\u00020\b2\u0006\u0010\u000e\u001a\u00020\b¢\u0006\u0004\b\u0011\u0010\u0010J%\u0010\u0015\u001a\u00020\u00022\u0006\u0010\u0012\u001a\u00020\b2\u0006\u0010\u0013\u001a\u00020\b2\u0006\u0010\u0014\u001a\u00020\b¢\u0006\u0004\b\u0015\u0010\rJ\u0015\u0010\u0017\u001a\u00020\u00022\u0006\u0010\u0016\u001a\u00020\b¢\u0006\u0004\b\u0017\u0010\u0018J%\u0010\u001a\u001a\u00020\u00022\u0006\u0010\t\u001a\u00020\b2\u0006\u0010\u0019\u001a\u00020\b2\u0006\u0010\u0016\u001a\u00020\b¢\u0006\u0004\b\u001a\u0010\rJ\u0015\u0010\u001b\u001a\u00020\u00022\u0006\u0010\u0019\u001a\u00020\b¢\u0006\u0004\b\u001b\u0010\u0018J\u001d\u0010\u001e\u001a\u00020\u00022\u0006\u0010\u001c\u001a\u00020\b2\u0006\u0010\u001d\u001a\u00020\b¢\u0006\u0004\b\u001e\u0010\u0010J#\u0010!\u001a\b\u0012\u0004\u0012\u00020 0\u001f2\u0006\u0010\u001c\u001a\u00020\b2\u0006\u0010\u001d\u001a\u00020\b¢\u0006\u0004\b!\u0010\"J\r\u0010#\u001a\u00020\u0002¢\u0006\u0004\b#\u0010\u0004J\r\u0010$\u001a\u00020\u0002¢\u0006\u0004\b$\u0010\u0004J\r\u0010%\u001a\u00020\u0002¢\u0006\u0004\b%\u0010\u0004J!\u0010)\u001a\u00020\u00022\b\b\u0002\u0010'\u001a\u00020&2\b\b\u0002\u0010(\u001a\u00020&¢\u0006\u0004\b)\u0010*J\u0015\u0010+\u001a\u00020\u00022\u0006\u0010\u001d\u001a\u00020\b¢\u0006\u0004\b+\u0010\u0018J\r\u0010,\u001a\u00020\u0002¢\u0006\u0004\b,\u0010\u0004J\u0015\u0010/\u001a\u00020\u00022\u0006\u0010.\u001a\u00020-¢\u0006\u0004\b/\u00100J\u0013\u00102\u001a\b\u0012\u0004\u0012\u0002010\u001f¢\u0006\u0004\b2\u00103J\u0013\u00104\u001a\b\u0012\u0004\u0012\u00020\b0\u001f¢\u0006\u0004\b4\u00103J\u0019\u00107\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u000206050\u001f¢\u0006\u0004\b7\u00103R#\u0010=\u001a\b\u0012\u0004\u0012\u00020&088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b9\u0010:\u001a\u0004\b;\u0010<R#\u0010A\u001a\b\u0012\u0004\u0012\u00020>088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b?\u0010:\u001a\u0004\b@\u0010<R#\u0010E\u001a\b\u0012\u0004\u0012\u00020B088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bC\u0010:\u001a\u0004\bD\u0010<R#\u0010H\u001a\b\u0012\u0004\u0012\u000201088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bF\u0010:\u001a\u0004\bG\u0010<R#\u0010K\u001a\b\u0012\u0004\u0012\u00020\b088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bI\u0010:\u001a\u0004\bJ\u0010<R#\u0010N\u001a\b\u0012\u0004\u0012\u00020&088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bL\u0010:\u001a\u0004\bM\u0010<R#\u0010R\u001a\b\u0012\u0004\u0012\u00020O088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bP\u0010:\u001a\u0004\bQ\u0010<R#\u0010U\u001a\b\u0012\u0004\u0012\u00020&088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bS\u0010:\u001a\u0004\bT\u0010<R$\u0010W\u001a\u0004\u0018\u00010V8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bW\u0010X\u001a\u0004\bY\u0010Z\"\u0004\b[\u0010\\R#\u0010_\u001a\b\u0012\u0004\u0012\u00020&088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b]\u0010:\u001a\u0004\b^\u0010<R#\u0010b\u001a\b\u0012\u0004\u0012\u00020&088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b`\u0010:\u001a\u0004\ba\u0010<R)\u0010f\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u0002060c088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bd\u0010:\u001a\u0004\be\u0010<R\u0018\u0010g\u001a\u0004\u0018\u00010V8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bg\u0010XR#\u0010j\u001a\b\u0012\u0004\u0012\u00020&088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bh\u0010:\u001a\u0004\bi\u0010<R#\u0010n\u001a\b\u0012\u0004\u0012\u00020k088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bl\u0010:\u001a\u0004\bm\u0010<R#\u0010q\u001a\b\u0012\u0004\u0012\u00020&088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bo\u0010:\u001a\u0004\bp\u0010<R#\u0010t\u001a\b\u0012\u0004\u0012\u00020&088F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\br\u0010:\u001a\u0004\bs\u0010<R\u001c\u0010u\u001a\u00020\b8\u0006@\u0006X\u0086D¢\u0006\f\n\u0004\bu\u0010v\u001a\u0004\bw\u0010xR\u001d\u0010}\u001a\u00020y8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bz\u0010:\u001a\u0004\b{\u0010|R%\u0010\u0081\u0001\u001a\b\u0012\u0004\u0012\u00020~088F@\u0006X\u0086\u0084\u0002¢\u0006\r\n\u0004\b\u007f\u0010:\u001a\u0005\b\u0080\u0001\u0010<¨\u0006\u0084\u0001"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "startTimeCountDown", "()V", "onCreate", "onDestroy", "getPicCode", "", "phone", "captcha", "token", "sendSmsCode", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", "smsCode", "bindPhone", "(Ljava/lang/String;Ljava/lang/String;)V", "findByPhone", "account_name", "account_password", "type", "loginPwd", "password", "setPwd", "(Ljava/lang/String;)V", "code", "updatePwd", "loginByCard", "filed", "value", "updateUserInfo", "Lc/a/b2/b;", "", "updateInfo", "(Ljava/lang/String;Ljava/lang/String;)Lc/a/b2/b;", "deleteAllCacheList", "deleteAllList", "loadAvatar", "", "hasLoading", "hideLoading", "requestUserInfo", "(ZZ)V", "bindParent", "loadAppInfo", "", "page", "appStore", "(I)V", "Lcom/jbzd/media/movecartoons/bean/response/UserInfoBean;", "userInfoV2", "()Lc/a/b2/b;", "getUserVipN", "", "Lcom/jbzd/media/movecartoons/bean/response/HeadImageBean$HeadImagesBean;", "userImages", "Landroidx/lifecycle/MutableLiveData;", "setPwdSuccess$delegate", "Lkotlin/Lazy;", "getSetPwdSuccess", "()Landroidx/lifecycle/MutableLiveData;", "setPwdSuccess", "Lcom/jbzd/media/movecartoons/bean/response/system/SystemInfoBean;", "sysTem$delegate", "getSysTem", "sysTem", "Lcom/jbzd/media/movecartoons/bean/response/FindBean;", "updatePwdSuccess$delegate", "getUpdatePwdSuccess", "updatePwdSuccess", "userInfo$delegate", "getUserInfo", "userInfo", "sendSmsText$delegate", "getSendSmsText", "sendSmsText", "loginPwdSuccess$delegate", "getLoginPwdSuccess", "loginPwdSuccess", "Lcom/jbzd/media/movecartoons/bean/response/PicVefBean;", "picVefBean$delegate", "getPicVefBean", "picVefBean", "loginCardSuccess$delegate", "getLoginCardSuccess", "loginCardSuccess", "Lc/a/d1;", "requestJob", "Lc/a/d1;", "getRequestJob", "()Lc/a/d1;", "setRequestJob", "(Lc/a/d1;)V", "userInfoUpdateSuccess$delegate", "getUserInfoUpdateSuccess", "userInfoUpdateSuccess", "historyUpdateSuccess$delegate", "getHistoryUpdateSuccess", "historyUpdateSuccess", "", "avatarBean$delegate", "getAvatarBean", "avatarBean", "timeCountDownJob", "loginPhoneSuccess$delegate", "getLoginPhoneSuccess", "loginPhoneSuccess", "Lb/w/b/b/f/a;", "loadingCardLogin$delegate", "getLoadingCardLogin", "loadingCardLogin", "findByPhoneSuccess$delegate", "getFindByPhoneSuccess", "findByPhoneSuccess", "bindPhoneSuccess$delegate", "getBindPhoneSuccess", "bindPhoneSuccess", "sendSmsButtonText", "Ljava/lang/String;", "getSendSmsButtonText", "()Ljava/lang/String;", "Lb/a/a/a/r/n/a;", "repository$delegate", "getRepository", "()Lb/a/a/a/r/n/a;", "repository", "Lcom/jbzd/media/movecartoons/bean/response/AppBean;", "appBean$delegate", "getAppBean", "appBean", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MineViewModel extends BaseViewModel {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Nullable
    private InterfaceC3053d1 requestJob;

    @Nullable
    private InterfaceC3053d1 timeCountDownJob;

    /* renamed from: repository$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy repository = LazyKt__LazyJVMKt.lazy(new Function0<C0944a>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$repository$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C0944a invoke() {
            return new C0944a();
        }
    });

    @NotNull
    private final String sendSmsButtonText = "获取验证码";

    /* renamed from: loadingCardLogin$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy loadingCardLogin = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<C2848a>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$loadingCardLogin$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<C2848a> invoke() {
            return new MutableLiveData<>(new C2848a(false, null, false, false, 15));
        }
    });

    /* renamed from: sendSmsText$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy sendSmsText = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$sendSmsText$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>("获取验证码");
        }
    });

    /* renamed from: picVefBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy picVefBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<PicVefBean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$picVefBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<PicVefBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: userInfo$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy userInfo = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<UserInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$userInfo$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<UserInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: loginPhoneSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy loginPhoneSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$loginPhoneSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: bindPhoneSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy bindPhoneSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$bindPhoneSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: findByPhoneSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy findByPhoneSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$findByPhoneSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: loginPwdSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy loginPwdSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$loginPwdSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: setPwdSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy setPwdSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$setPwdSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: updatePwdSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy updatePwdSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<FindBean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$updatePwdSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<FindBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: loginCardSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy loginCardSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$loginCardSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: sysTem$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy sysTem = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<SystemInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$sysTem$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<SystemInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: userInfoUpdateSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy userInfoUpdateSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$userInfoUpdateSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: appBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy appBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<AppBean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$appBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<AppBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: historyUpdateSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy historyUpdateSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$historyUpdateSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: avatarBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy avatarBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<? extends HeadImageBean.HeadImagesBean>>>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$avatarBean$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<? extends HeadImageBean.HeadImagesBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000b\u0010\u0004J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004J%\u0010\t\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0007\u001a\u00020\u00052\u0006\u0010\b\u001a\u00020\u0005¢\u0006\u0004\b\t\u0010\n¨\u0006\f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel$Companion;", "", "", "getUserInfo", "()V", "", "object_type", "object_id", "object_name", "systemTrack", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void getUserInfo() {
            C0917a.m221e(C0917a.f372a, "user/info", UserInfoBean.class, null, new Function1<UserInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$Companion$getUserInfo$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(UserInfoBean userInfoBean) {
                    invoke2(userInfoBean);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable UserInfoBean userInfoBean) {
                    if (userInfoBean == null) {
                        return;
                    }
                    MyApp myApp = MyApp.f9891f;
                    MyApp.m4189j(userInfoBean);
                }
            }, null, false, false, null, false, CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION);
        }

        public final void systemTrack(@NotNull String object_type, @NotNull String object_id, @NotNull String object_name) {
            Intrinsics.checkNotNullParameter(object_type, "object_type");
            Intrinsics.checkNotNullParameter(object_id, "object_id");
            Intrinsics.checkNotNullParameter(object_name, "object_name");
            C0917a c0917a = C0917a.f372a;
            HashMap m596R = C1499a.m596R("object_type", object_type, "object_id", object_id);
            m596R.put("object_name", object_name);
            Unit unit = Unit.INSTANCE;
            C0917a.m221e(c0917a, "system/track", String.class, m596R, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$Companion$systemTrack$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(String str) {
                    invoke2(str);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable String str) {
                }
            }, null, false, false, null, false, 496);
        }
    }

    private final C0944a getRepository() {
        return (C0944a) this.repository.getValue();
    }

    public static /* synthetic */ void requestUserInfo$default(MineViewModel mineViewModel, boolean z, boolean z2, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = false;
        }
        if ((i2 & 2) != 0) {
            z2 = true;
        }
        mineViewModel.requestUserInfo(z, z2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void startTimeCountDown() {
        cancelJob(this.timeCountDownJob);
        this.timeCountDownJob = C2354n.m2435U0(C3109w0.f8471c, null, 0, new MineViewModel$startTimeCountDown$1(this, null), 3, null);
    }

    public final void appStore(int page) {
        getLoading().setValue(new C2848a(true, null, true, false, 10));
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("page", String.valueOf(page));
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "system/appStore", AppBean.class, hashMap, new Function1<AppBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$appStore$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(AppBean appBean) {
                invoke2(appBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable AppBean appBean) {
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                if (appBean != null) {
                    MineViewModel.this.getAppBean().setValue(appBean);
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$appStore$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 480);
    }

    public final void bindParent(@NotNull final String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("code", StringsKt__StringsJVMKt.replace$default(value, "share://", "", false, 4, (Object) null));
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "user/bindParent", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$bindParent$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                C2354n.m2409L1("绑定成功");
                MyApp myApp = MyApp.f9891f;
                MyApp.f9892g.parent_name = value;
                this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                this.getUserInfoUpdateSuccess().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$bindParent$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                C2354n.m2449Z(it.getMessage());
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getUserInfoUpdateSuccess().setValue(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    public final void bindPhone(@NotNull String phone, @NotNull String smsCode) {
        Intrinsics.checkNotNullParameter(phone, "phone");
        Intrinsics.checkNotNullParameter(smsCode, "smsCode");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("phone", phone, "code", smsCode);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "user/bindPhone", TokenBean.class, m596R, new Function1<TokenBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$bindPhone$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TokenBean tokenBean) {
                invoke2(tokenBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable TokenBean tokenBean) {
                MyApp myApp = MyApp.f9891f;
                MyApp.m4188i(tokenBean);
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MutableLiveData<Boolean> loginPhoneSuccess = MineViewModel.this.getLoginPhoneSuccess();
                Boolean bool = Boolean.TRUE;
                loginPhoneSuccess.setValue(bool);
                MineViewModel.this.getBindPhoneSuccess().setValue(bool);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$bindPhone$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MutableLiveData<Boolean> loginPhoneSuccess = MineViewModel.this.getLoginPhoneSuccess();
                Boolean bool = Boolean.FALSE;
                loginPhoneSuccess.setValue(bool);
                MineViewModel.this.getBindPhoneSuccess().setValue(bool);
            }
        }, false, false, null, false, 480);
    }

    public final void deleteAllCacheList() {
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("ids", ChatMsgBean.SERVICE_ID);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "movie/delDownload", String.class, m595Q, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$deleteAllCacheList$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getHistoryUpdateSuccess().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$deleteAllCacheList$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getHistoryUpdateSuccess().setValue(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    public final void deleteAllList() {
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("ids", ChatMsgBean.SERVICE_ID);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "movie/delHistory", String.class, m595Q, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$deleteAllList$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getHistoryUpdateSuccess().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$deleteAllList$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getHistoryUpdateSuccess().setValue(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    public final void findByPhone(@NotNull String phone, @NotNull String smsCode) {
        Intrinsics.checkNotNullParameter(phone, "phone");
        Intrinsics.checkNotNullParameter(smsCode, "smsCode");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("phone", phone, "code", smsCode);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "user/findByPhone", TokenBean.class, m596R, new Function1<TokenBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$findByPhone$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TokenBean tokenBean) {
                invoke2(tokenBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable TokenBean tokenBean) {
                MyApp myApp = MyApp.f9891f;
                MyApp.m4188i(tokenBean);
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getFindByPhoneSuccess().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$findByPhone$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getFindByPhoneSuccess().setValue(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    @NotNull
    public final MutableLiveData<AppBean> getAppBean() {
        return (MutableLiveData) this.appBean.getValue();
    }

    @NotNull
    public final MutableLiveData<List<HeadImageBean.HeadImagesBean>> getAvatarBean() {
        return (MutableLiveData) this.avatarBean.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getBindPhoneSuccess() {
        return (MutableLiveData) this.bindPhoneSuccess.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getFindByPhoneSuccess() {
        return (MutableLiveData) this.findByPhoneSuccess.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getHistoryUpdateSuccess() {
        return (MutableLiveData) this.historyUpdateSuccess.getValue();
    }

    @NotNull
    public final MutableLiveData<C2848a> getLoadingCardLogin() {
        return (MutableLiveData) this.loadingCardLogin.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getLoginCardSuccess() {
        return (MutableLiveData) this.loginCardSuccess.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getLoginPhoneSuccess() {
        return (MutableLiveData) this.loginPhoneSuccess.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getLoginPwdSuccess() {
        return (MutableLiveData) this.loginPwdSuccess.getValue();
    }

    public final void getPicCode() {
        C0917a.m221e(C0917a.f372a, "system/captcha", PicVefBean.class, new HashMap(), new Function1<PicVefBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$getPicCode$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PicVefBean picVefBean) {
                invoke2(picVefBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable PicVefBean picVefBean) {
                MineViewModel.this.getPicVefBean().setValue(picVefBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$getPicCode$2
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 480);
    }

    @NotNull
    public final MutableLiveData<PicVefBean> getPicVefBean() {
        return (MutableLiveData) this.picVefBean.getValue();
    }

    @Nullable
    public final InterfaceC3053d1 getRequestJob() {
        return this.requestJob;
    }

    @NotNull
    public final String getSendSmsButtonText() {
        return this.sendSmsButtonText;
    }

    @NotNull
    public final MutableLiveData<String> getSendSmsText() {
        return (MutableLiveData) this.sendSmsText.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getSetPwdSuccess() {
        return (MutableLiveData) this.setPwdSuccess.getValue();
    }

    @NotNull
    public final MutableLiveData<SystemInfoBean> getSysTem() {
        return (MutableLiveData) this.sysTem.getValue();
    }

    @NotNull
    public final MutableLiveData<FindBean> getUpdatePwdSuccess() {
        return (MutableLiveData) this.updatePwdSuccess.getValue();
    }

    @NotNull
    public final MutableLiveData<UserInfoBean> getUserInfo() {
        return (MutableLiveData) this.userInfo.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getUserInfoUpdateSuccess() {
        return (MutableLiveData) this.userInfoUpdateSuccess.getValue();
    }

    @NotNull
    public final InterfaceC3006b<String> getUserVipN() {
        return getRepository().m287a().m231A();
    }

    public final void loadAppInfo() {
        getLoading().setValue(new C2848a(true, null, true, false, 10));
        C0917a.m221e(C0917a.f372a, "system/info", SystemInfoBean.class, new RequestSystemInfoBody(C0887j.m211a(), "main", C0925i.f437a.m269a(), "2"), new Function1<SystemInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$loadAppInfo$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(SystemInfoBean systemInfoBean) {
                invoke2(systemInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable SystemInfoBean systemInfoBean) {
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                if (systemInfoBean == null) {
                    return;
                }
                MineViewModel mineViewModel = MineViewModel.this;
                MyApp myApp = MyApp.f9891f;
                MyApp.m4187h(systemInfoBean);
                mineViewModel.getSysTem().setValue(systemInfoBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$loadAppInfo$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 480);
    }

    public final void loadAvatar() {
        cancelJob(this.requestJob);
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        this.requestJob = C0917a.m222f(C0917a.f372a, "user/images", HeadImageBean.HeadImagesBean.class, null, new Function1<List<? extends HeadImageBean.HeadImagesBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$loadAvatar$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends HeadImageBean.HeadImagesBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends HeadImageBean.HeadImagesBean> list) {
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getAvatarBean().setValue(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$loadAvatar$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 484);
    }

    public final void loginByCard(@NotNull String code) {
        Intrinsics.checkNotNullParameter(code, "code");
        getLoadingCardLogin().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("code", code);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "user/findQrcode", TokenBean.class, m595Q, new Function1<TokenBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$loginByCard$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TokenBean tokenBean) {
                invoke2(tokenBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable TokenBean tokenBean) {
                MyApp myApp = MyApp.f9891f;
                MyApp.m4188i(tokenBean);
                MineViewModel.this.getLoadingCardLogin().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getLoginCardSuccess().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$loginByCard$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getLoadingCardLogin().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getLoginCardSuccess().setValue(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    public final void loginPwd(@NotNull String account_name, @NotNull String account_password, @NotNull String type) {
        Intrinsics.checkNotNullParameter(account_name, "account_name");
        Intrinsics.checkNotNullParameter(account_password, "account_password");
        Intrinsics.checkNotNullParameter(type, "type");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("account_name", account_name, "account_password", account_password);
        m596R.put("type", type);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "user/findByAccount", TokenBean.class, m596R, new Function1<TokenBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$loginPwd$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TokenBean tokenBean) {
                invoke2(tokenBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable TokenBean tokenBean) {
                MyApp myApp = MyApp.f9891f;
                MyApp.m4188i(tokenBean);
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getLoginPwdSuccess().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$loginPwd$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getLoginPwdSuccess().setValue(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.timeCountDownJob);
    }

    public final void requestUserInfo(boolean hasLoading, final boolean hideLoading) {
        cancelJob(this.requestJob);
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        this.requestJob = C0917a.m221e(C0917a.f372a, "user/info", UserInfoBean.class, null, new Function1<UserInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$requestUserInfo$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(UserInfoBean userInfoBean) {
                invoke2(userInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable UserInfoBean userInfoBean) {
                if (hideLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                if (userInfoBean == null) {
                    return;
                }
                MineViewModel mineViewModel = this;
                MyApp myApp = MyApp.f9891f;
                MyApp.m4189j(userInfoBean);
                mineViewModel.getUserInfo().setValue(userInfoBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$requestUserInfo$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hideLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 484);
    }

    public final void sendSmsCode(@NotNull String phone, @NotNull String captcha, @NotNull String token) {
        Intrinsics.checkNotNullParameter(phone, "phone");
        Intrinsics.checkNotNullParameter(captcha, "captcha");
        Intrinsics.checkNotNullParameter(token, "token");
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("phone", phone, "captcha", captcha);
        m596R.put("token", token);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "system/sendSms", String.class, m596R, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$sendSmsCode$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                MineViewModel.this.startTimeCountDown();
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$sendSmsCode$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getSendSmsText().setValue(MineViewModel.this.getSendSmsButtonText());
            }
        }, false, false, null, false, 480);
    }

    public final void setPwd(@NotNull String password) {
        Intrinsics.checkNotNullParameter(password, "password");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("password", password);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "user/setPassword", Object.class, m595Q, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$setPwd$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                invoke2(obj);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable Object obj) {
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getSetPwdSuccess().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$setPwd$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getSetPwdSuccess().setValue(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    public final void setRequestJob(@Nullable InterfaceC3053d1 interfaceC3053d1) {
        this.requestJob = interfaceC3053d1;
    }

    @NotNull
    public final InterfaceC3006b<Object> updateInfo(@NotNull String filed, @NotNull String value) {
        Intrinsics.checkNotNullParameter(filed, "filed");
        Intrinsics.checkNotNullParameter(value, "value");
        C0944a repository = getRepository();
        Objects.requireNonNull(repository);
        Intrinsics.checkNotNullParameter(filed, "field");
        Intrinsics.checkNotNullParameter(value, "nickName");
        return repository.m287a().m254m(filed, value);
    }

    public final void updatePwd(@NotNull String phone, @NotNull String code, @NotNull String password) {
        Intrinsics.checkNotNullParameter(phone, "phone");
        Intrinsics.checkNotNullParameter(code, "code");
        Intrinsics.checkNotNullParameter(password, "password");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("phone", phone, "code", code);
        m596R.put("password", password);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "user/findPwdByPhone", FindBean.class, m596R, new Function1<FindBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$updatePwd$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(FindBean findBean) {
                invoke2(findBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable FindBean findBean) {
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MutableLiveData<FindBean> updatePwdSuccess = MineViewModel.this.getUpdatePwdSuccess();
                if (findBean == null) {
                    findBean = new FindBean();
                }
                updatePwdSuccess.setValue(findBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$updatePwd$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getUpdatePwdSuccess().setValue(null);
            }
        }, false, false, null, false, 480);
    }

    public final void updateUserInfo(@NotNull String filed, @NotNull String value) {
        Intrinsics.checkNotNullParameter(filed, "filed");
        Intrinsics.checkNotNullParameter(value, "value");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("field", filed, "value", value);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "user/updateInfo", String.class, m596R, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$updateUserInfo$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getUserInfoUpdateSuccess().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.MineViewModel$updateUserInfo$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                MineViewModel.this.getUserInfoUpdateSuccess().setValue(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    @NotNull
    public final InterfaceC3006b<List<HeadImageBean.HeadImagesBean>> userImages() {
        return getRepository().m287a().m248g();
    }

    @NotNull
    public final InterfaceC3006b<UserInfoBean> userInfoV2() {
        return getRepository().m288b();
    }
}
