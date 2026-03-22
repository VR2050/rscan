package com.jbzd.media.movecartoons.p396ui.splash;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.SharedPreferences;
import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.OnlineServiceBean;
import com.jbzd.media.movecartoons.bean.TokenBean;
import com.jbzd.media.movecartoons.bean.request.RequestSystemInfoBody;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.PicVefBean;
import com.jbzd.media.movecartoons.bean.response.system.SystemInfoBean;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import com.yalantis.ucrop.view.CropImageView;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.C0884g;
import p005b.p006a.p007a.p008a.C0885h;
import p005b.p006a.p007a.p008a.C0887j;
import p005b.p006a.p007a.p008a.p009a.C0854k;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p006a.p007a.p008a.p017r.C0925i;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p005b.p327w.p330b.p336c.C2853d;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000F\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0017\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\b\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\bA\u0010\u0012J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004JO\u0010\u000f\u001a\u00020\r2\u0006\u0010\u0006\u001a\u00020\u000526\u0010\u000e\u001a2\u0012\u0013\u0012\u00110\b¢\u0006\f\b\t\u0012\b\b\n\u0012\u0004\b\b(\u000b\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b\t\u0012\b\b\n\u0012\u0004\b\b(\f\u0012\u0004\u0012\u00020\r0\u0007H\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\rH\u0002¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\rH\u0016¢\u0006\u0004\b\u0013\u0010\u0012J\r\u0010\u0014\u001a\u00020\r¢\u0006\u0004\b\u0014\u0010\u0012J'\u0010\u0018\u001a\u00020\r2\u0006\u0010\u0015\u001a\u00020\u00022\u0006\u0010\u0016\u001a\u00020\u00022\b\b\u0002\u0010\u0017\u001a\u00020\b¢\u0006\u0004\b\u0018\u0010\u0019J\u001f\u0010\u001a\u001a\u00020\r2\u0006\u0010\u0015\u001a\u00020\u00022\b\b\u0002\u0010\u0017\u001a\u00020\b¢\u0006\u0004\b\u001a\u0010\u001bJ\r\u0010\u001c\u001a\u00020\r¢\u0006\u0004\b\u001c\u0010\u0012J\r\u0010\u001d\u001a\u00020\r¢\u0006\u0004\b\u001d\u0010\u0012J\r\u0010\u001e\u001a\u00020\r¢\u0006\u0004\b\u001e\u0010\u0012J\u001d\u0010!\u001a\u00020\r2\u0006\u0010\u001f\u001a\u00020\u00022\u0006\u0010 \u001a\u00020\u0002¢\u0006\u0004\b!\u0010\"J\u0015\u0010#\u001a\u00020\r2\u0006\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b#\u0010$R#\u0010#\u001a\b\u0012\u0004\u0012\u00020\b0%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b&\u0010'\u001a\u0004\b(\u0010)R#\u0010,\u001a\b\u0012\u0004\u0012\u00020\b0%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b*\u0010'\u001a\u0004\b+\u0010)R\u001f\u0010/\u001a\u0004\u0018\u00010\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b-\u0010'\u001a\u0004\b.\u0010\u0004R\u001f\u00102\u001a\u0004\u0018\u00010\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b0\u0010'\u001a\u0004\b1\u0010\u0004R#\u00106\u001a\b\u0012\u0004\u0012\u0002030%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b4\u0010'\u001a\u0004\b5\u0010)R#\u00109\u001a\b\u0012\u0004\u0012\u00020\b0%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b7\u0010'\u001a\u0004\b8\u0010)R#\u0010=\u001a\b\u0012\u0004\u0012\u00020:0%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b;\u0010'\u001a\u0004\b<\u0010)R#\u0010@\u001a\b\u0012\u0004\u0012\u00020\b0%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b>\u0010'\u001a\u0004\b?\u0010)¨\u0006B"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/splash/SplashViewMode;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "getClipboardStr", "()Ljava/lang/String;", "", "index", "Lkotlin/Function2;", "", "Lkotlin/ParameterName;", "name", FindBean.status_success, "url", "", "resultCallback", "ping", "(ILkotlin/jvm/functions/Function2;)V", "requestSystemInfo", "()V", "onCreate", "startPing", "key", "codeValue", "hasLoading", "systemUnlock", "(Ljava/lang/String;Ljava/lang/String;Z)V", "systemCaptcha", "(Ljava/lang/String;Z)V", "bindChannel", "bindParent", "getSystemService", "captcha_key", "captcha_value", "requestSystemInfoNew", "(Ljava/lang/String;Ljava/lang/String;)V", "systemCdn", "(Ljava/lang/String;)V", "Landroidx/lifecycle/MutableLiveData;", "systemCdn$delegate", "Lkotlin/Lazy;", "getSystemCdn", "()Landroidx/lifecycle/MutableLiveData;", "lineError$delegate", "getLineError", "lineError", "clipboardValue$delegate", "getClipboardValue", "clipboardValue", "channel$delegate", "getChannel", "channel", "Lcom/jbzd/media/movecartoons/bean/response/system/SystemInfoBean;", "systemInfoBody$delegate", "getSystemInfoBody", "systemInfoBody", "lineSuccess$delegate", "getLineSuccess", "lineSuccess", "Lcom/jbzd/media/movecartoons/bean/response/PicVefBean;", "picVefBean$delegate", "getPicVefBean", "picVefBean", "picVerState$delegate", "getPicVerState", "picVerState", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SplashViewMode extends BaseViewModel {

    /* renamed from: systemCdn$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy systemCdn = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$systemCdn$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>(Boolean.FALSE);
        }
    });

    /* renamed from: lineError$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy lineError = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$lineError$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>(Boolean.FALSE);
        }
    });

    /* renamed from: lineSuccess$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy lineSuccess = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$lineSuccess$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>(Boolean.FALSE);
        }
    });

    /* renamed from: systemInfoBody$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy systemInfoBody = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<SystemInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$systemInfoBody$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<SystemInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: clipboardValue$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy clipboardValue = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$clipboardValue$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String clipboardStr;
            clipboardStr = SplashViewMode.this.getClipboardStr();
            return clipboardStr;
        }
    });

    /* renamed from: channel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy channel = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$channel$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            C0854k c0854k = C0854k.f255a;
            String str = C0854k.f256b.get(0);
            return ((str == null || str.length() == 0) || Intrinsics.areEqual(C0854k.f256b.get(0), "null")) ? "" : Intrinsics.stringPlus("channel://", C0854k.f256b.get(0));
        }
    });

    /* renamed from: picVefBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy picVefBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<PicVefBean>>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$picVefBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<PicVefBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: picVerState$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy picVerState = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$picVerState$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* JADX INFO: Access modifiers changed from: private */
    public final String getClipboardStr() {
        Object systemService = C4195m.m4792Y().getSystemService("clipboard");
        Objects.requireNonNull(systemService, "null cannot be cast to non-null type android.content.ClipboardManager");
        ClipData primaryClip = ((ClipboardManager) systemService).getPrimaryClip();
        String value = "";
        if (primaryClip != null) {
            int itemCount = primaryClip.getItemCount() - 1;
            if (itemCount >= 0) {
                while (true) {
                    int i2 = itemCount - 1;
                    CharSequence str = primaryClip.getItemAt(itemCount).getText();
                    Intrinsics.stringPlus("strs:", str);
                    if (!(str == null || str.length() == 0)) {
                        Intrinsics.checkNotNullExpressionValue(str, "str");
                        if (StringsKt__StringsKt.contains$default(str, (CharSequence) "://", false, 2, (Object) null)) {
                            value = str.toString();
                        }
                    }
                    if (i2 < 0) {
                        break;
                    }
                    itemCount = i2;
                }
            }
            Intrinsics.checkNotNullParameter("CLIPBOARD_STR", "key");
            Intrinsics.checkNotNullParameter(value, "value");
            ApplicationC2828a applicationC2828a = C2827a.f7670a;
            if (applicationC2828a == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
            Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
            SharedPreferences.Editor editor = sharedPreferences.edit();
            Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
            editor.putString("CLIPBOARD_STR", value);
            editor.commit();
        }
        return value;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x006e, code lost:
    
        r4.add(r7);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void ping(int r12, kotlin.jvm.functions.Function2<? super java.lang.Boolean, ? super java.lang.String, kotlin.Unit> r13) {
        /*
            Method dump skipped, instructions count: 366
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.splash.SplashViewMode.ping(int, kotlin.jvm.functions.Function2):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void requestSystemInfo() {
        C0917a c0917a = C0917a.f372a;
        String m211a = C0887j.m211a();
        String clipboardStr = getClipboardStr();
        C0854k c0854k = C0854k.f255a;
        C0917a.m221e(c0917a, "system/info", SystemInfoBean.class, new RequestSystemInfoBody(m211a, clipboardStr, (String) CollectionsKt___CollectionsKt.last((List) C0854k.f256b), getChannel(), C0925i.f437a.m269a(), "2"), new Function1<SystemInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$requestSystemInfo$1
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
                SplashViewMode.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                if (systemInfoBean == null) {
                    return;
                }
                SplashViewMode splashViewMode = SplashViewMode.this;
                List<String> sites = systemInfoBean.domains;
                if (sites != null) {
                    Intrinsics.checkNotNullExpressionValue(sites, "it.domains");
                    Intrinsics.checkNotNullParameter(sites, "sites");
                    if (!sites.isEmpty()) {
                        String value = CollectionsKt___CollectionsKt.joinToString$default(sites, ChineseToPinyinResource.Field.COMMA, null, null, 0, null, C0884g.f328c, 30, null);
                        Intrinsics.checkNotNullParameter("default_sites", "key");
                        Intrinsics.checkNotNullParameter(value, "value");
                        ApplicationC2828a applicationC2828a = C2827a.f7670a;
                        if (applicationC2828a == null) {
                            Intrinsics.throwUninitializedPropertyAccessException("context");
                            throw null;
                        }
                        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
                        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
                        SharedPreferences.Editor editor = sharedPreferences.edit();
                        Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
                        editor.putString("default_sites", value);
                        editor.commit();
                    }
                }
                C2853d c2853d = C2853d.f7770a;
                String str = systemInfoBean.cdn_header;
                Intrinsics.checkNotNullExpressionValue(str, "it.cdn_header");
                Intrinsics.checkNotNullParameter(str, "<set-?>");
                C2853d.f7771b = str;
                String str2 = systemInfoBean.service_email;
                Intrinsics.checkNotNullExpressionValue(str2, "it.service_email");
                Intrinsics.checkNotNullParameter(str2, "<set-?>");
                C0885h.f329a = str2;
                String str3 = systemInfoBean.service_link;
                Intrinsics.checkNotNullExpressionValue(str3, "it.service_link");
                Intrinsics.checkNotNullParameter(str3, "<set-?>");
                MyApp myApp = MyApp.f9891f;
                MyApp.m4187h(systemInfoBean);
                TokenBean tokenBean = systemInfoBean.token;
                if (tokenBean != null) {
                    MyApp.m4188i(tokenBean);
                }
                splashViewMode.getSystemInfoBody().setValue(systemInfoBean);
                MineViewModel.INSTANCE.getUserInfo();
                if (Intrinsics.areEqual(systemInfoBean.customer_system_status, "y")) {
                    splashViewMode.getSystemService();
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$requestSystemInfo$2
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
                SplashViewMode.this.getLineError().setValue(Boolean.TRUE);
            }
        }, false, true, null, false, 416);
    }

    public static /* synthetic */ void systemCaptcha$default(SplashViewMode splashViewMode, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = false;
        }
        splashViewMode.systemCaptcha(str, z);
    }

    public static /* synthetic */ void systemUnlock$default(SplashViewMode splashViewMode, String str, String str2, boolean z, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            z = true;
        }
        splashViewMode.systemUnlock(str, str2, z);
    }

    public final void bindChannel() {
        String channel = getChannel();
        if (channel == null || channel.length() == 0) {
            return;
        }
        HashMap hashMap = new HashMap();
        String channel2 = getChannel();
        Intrinsics.checkNotNull(channel2);
        hashMap.put("code", String.valueOf(channel2));
        C0917a.m221e(C0917a.f372a, "user/bindParent", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$bindChannel$2
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
            }
        }, null, false, false, null, false, 432);
    }

    public final void bindParent() {
        String clipboardValue = getClipboardValue();
        if (clipboardValue == null || clipboardValue.length() == 0) {
            return;
        }
        HashMap hashMap = new HashMap();
        String clipboardValue2 = getClipboardValue();
        Intrinsics.checkNotNull(clipboardValue2);
        hashMap.put("code", String.valueOf(StringsKt__StringsJVMKt.replace$default(clipboardValue2, "share://", "", false, 4, (Object) null)));
        C0917a.m221e(C0917a.f372a, "user/bindParent", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$bindParent$2
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
            }
        }, null, false, false, null, false, 432);
    }

    @Nullable
    public final String getChannel() {
        return (String) this.channel.getValue();
    }

    @Nullable
    public final String getClipboardValue() {
        return (String) this.clipboardValue.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getLineError() {
        return (MutableLiveData) this.lineError.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getLineSuccess() {
        return (MutableLiveData) this.lineSuccess.getValue();
    }

    @NotNull
    public final MutableLiveData<PicVefBean> getPicVefBean() {
        return (MutableLiveData) this.picVefBean.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getPicVerState() {
        return (MutableLiveData) this.picVerState.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getSystemCdn() {
        return (MutableLiveData) this.systemCdn.getValue();
    }

    @NotNull
    public final MutableLiveData<SystemInfoBean> getSystemInfoBody() {
        return (MutableLiveData) this.systemInfoBody.getValue();
    }

    public final void getSystemService() {
        C0917a.m221e(C0917a.f372a, "user/getCustomerUrl", OnlineServiceBean.class, null, new Function1<OnlineServiceBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$getSystemService$1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(OnlineServiceBean onlineServiceBean) {
                invoke2(onlineServiceBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable OnlineServiceBean onlineServiceBean) {
                MyApp myApp = MyApp.f9891f;
                MyApp.f9897l = onlineServiceBean == null ? null : onlineServiceBean.getUrl();
            }
        }, null, false, false, null, false, CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION);
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
        startPing();
    }

    public final void requestSystemInfoNew(@NotNull String captcha_key, @NotNull String captcha_value) {
        Intrinsics.checkNotNullParameter(captcha_key, "captcha_key");
        Intrinsics.checkNotNullParameter(captcha_value, "captcha_value");
        C0917a.m221e(C0917a.f372a, "system/info", SystemInfoBean.class, new RequestSystemInfoBody(captcha_key, captcha_value, C0887j.m211a(), getClipboardStr(), "main", getChannel(), C0925i.f437a.m269a(), "2"), new Function1<SystemInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$requestSystemInfoNew$1
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
                SplashViewMode.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                if (systemInfoBean == null) {
                    return;
                }
                SplashViewMode splashViewMode = SplashViewMode.this;
                C2853d c2853d = C2853d.f7770a;
                String str = systemInfoBean.cdn_header;
                Intrinsics.checkNotNullExpressionValue(str, "it.cdn_header");
                Intrinsics.checkNotNullParameter(str, "<set-?>");
                C2853d.f7771b = str;
                String str2 = systemInfoBean.service_email;
                Intrinsics.checkNotNullExpressionValue(str2, "it.service_email");
                Intrinsics.checkNotNullParameter(str2, "<set-?>");
                C0885h.f329a = str2;
                String str3 = systemInfoBean.service_link;
                Intrinsics.checkNotNullExpressionValue(str3, "it.service_link");
                Intrinsics.checkNotNullParameter(str3, "<set-?>");
                MyApp myApp = MyApp.f9891f;
                MyApp.m4187h(systemInfoBean);
                TokenBean tokenBean = systemInfoBean.token;
                if (tokenBean != null) {
                    MyApp.m4188i(tokenBean);
                }
                splashViewMode.getSystemInfoBody().setValue(systemInfoBean);
                MineViewModel.INSTANCE.getUserInfo();
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$requestSystemInfoNew$2
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
                SplashViewMode.this.getLineError().setValue(Boolean.TRUE);
            }
        }, false, false, null, false, 416);
    }

    public final void startPing() {
        ping(0, new Function2<Boolean, String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$startPing$1
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(Boolean bool, String str) {
                invoke(bool.booleanValue(), str);
                return Unit.INSTANCE;
            }

            public final void invoke(boolean z, @NotNull String value) {
                Intrinsics.checkNotNullParameter(value, "url");
                SplashViewMode.this.getLineError().setValue(Boolean.valueOf(!z));
                C0925i c0925i = C0925i.f437a;
                Intrinsics.checkNotNullParameter(value, "validUrl");
                C0925i.f438b = value;
                Intrinsics.checkNotNullParameter("SP_BASE_URL", "key");
                Intrinsics.checkNotNullParameter(value, "value");
                ApplicationC2828a applicationC2828a = C2827a.f7670a;
                if (applicationC2828a == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("context");
                    throw null;
                }
                SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
                Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
                SharedPreferences.Editor editor = sharedPreferences.edit();
                Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
                editor.putString("SP_BASE_URL", value);
                editor.commit();
                if (z) {
                    SplashViewMode.this.getLineSuccess().setValue(Boolean.TRUE);
                    SplashViewMode.this.requestSystemInfo();
                }
            }
        });
    }

    public final void systemCaptcha(@NotNull String key, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(key, "key");
        HashMap hashMap = new HashMap();
        hashMap.put("key", key);
        C0917a.m221e(C0917a.f372a, "system/captcha", PicVefBean.class, hashMap, new Function1<PicVefBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$systemCaptcha$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getPicVefBean().setValue(picVefBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$systemCaptcha$2
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
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    public final void systemCdn(@NotNull String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("name", name);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "system/cdn", String.class, m595Q, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$systemCdn$5
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
                SplashViewMode.this.getSystemCdn().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$systemCdn$6
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
                SplashViewMode.this.getSystemCdn().setValue(Boolean.FALSE);
            }
        }, false, false, null, false, 416);
    }

    public final void systemUnlock(@NotNull String key, @NotNull String codeValue, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(codeValue, "codeValue");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("key", key);
        hashMap.put("value", codeValue);
        C0917a.m221e(C0917a.f372a, "system/unlock", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$systemUnlock$1
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
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getPicVerState().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.splash.SplashViewMode$systemUnlock$2
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
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getPicVerState().setValue(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }
}
