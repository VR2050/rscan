package com.jbzd.media.movecartoons;

import android.content.SharedPreferences;
import android.content.res.Resources;
import com.alibaba.fastjson.JSON;
import com.jbzd.media.movecartoons.bean.TokenBean;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.bean.response.system.SystemInfoBean;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0006\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\n\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u0017\u0010\u0007\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\t\u0010\u0004¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/MyApp;", "Lb/w/b/b/a;", "", "onCreate", "()V", "", "level", "onTrimMemory", "(I)V", "onLowMemory", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MyApp extends ApplicationC2828a {

    /* renamed from: f */
    @NotNull
    public static final MyApp f9891f = null;

    /* renamed from: g */
    @NotNull
    public static UserInfoBean f9892g = new UserInfoBean();

    /* renamed from: h */
    @NotNull
    public static String f9893h = "0";

    /* renamed from: i */
    public static MyApp f9894i;

    /* renamed from: j */
    public static Resources f9895j;

    /* renamed from: k */
    @Nullable
    public static SystemInfoBean f9896k;

    /* renamed from: l */
    @Nullable
    public static String f9897l;

    /* renamed from: m */
    @Nullable
    public static TokenBean f9898m;

    @NotNull
    /* renamed from: d */
    public static final MyApp m4183d() {
        MyApp myApp = f9894i;
        if (myApp != null) {
            return myApp;
        }
        Intrinsics.throwUninitializedPropertyAccessException("instance");
        throw null;
    }

    @NotNull
    /* renamed from: e */
    public static final Resources m4184e() {
        Resources resources = f9895j;
        if (resources != null) {
            return resources;
        }
        Intrinsics.throwUninitializedPropertyAccessException("resourses");
        throw null;
    }

    @NotNull
    /* renamed from: f */
    public static final SystemInfoBean m4185f() {
        SystemInfoBean systemInfoBean = f9896k;
        if (systemInfoBean != null) {
            return systemInfoBean;
        }
        Intrinsics.checkNotNullParameter("SYSTEM_INFO", "key");
        Intrinsics.checkNotNullParameter("", "default");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        String string = sharedPreferences.getString("SYSTEM_INFO", "");
        Intrinsics.checkNotNull(string);
        Object parseObject = JSON.parseObject(string, (Class<Object>) SystemInfoBean.class);
        Intrinsics.checkNotNullExpressionValue(parseObject, "parseObject(\n                    SPUtils.getString(Constants.KEY_SYSTEM_INFO),\n                    SystemInfoBean::class.java\n                )");
        return (SystemInfoBean) parseObject;
    }

    @Nullable
    /* renamed from: g */
    public static final TokenBean m4186g() {
        TokenBean tokenBean = f9898m;
        if (tokenBean != null) {
            return tokenBean;
        }
        Intrinsics.checkNotNullParameter("USER_TOKEN", "key");
        Intrinsics.checkNotNullParameter("", "default");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        String string = sharedPreferences.getString("USER_TOKEN", "");
        Intrinsics.checkNotNull(string);
        return (TokenBean) JSON.parseObject(string, TokenBean.class);
    }

    /* renamed from: h */
    public static final void m4187h(@NotNull SystemInfoBean value) {
        Intrinsics.checkNotNullParameter(value, "value");
        f9896k = value;
        String value2 = JSON.toJSONString(value);
        Intrinsics.checkNotNullExpressionValue(value2, "toJSONString(value)");
        Intrinsics.checkNotNullParameter("SYSTEM_INFO", "key");
        Intrinsics.checkNotNullParameter(value2, "value");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        SharedPreferences.Editor editor = sharedPreferences.edit();
        Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
        editor.putString("SYSTEM_INFO", value2);
        editor.commit();
    }

    /* renamed from: i */
    public static final void m4188i(@Nullable TokenBean tokenBean) {
        f9898m = tokenBean;
        String value = JSON.toJSONString(tokenBean);
        Intrinsics.checkNotNullExpressionValue(value, "toJSONString(value)");
        Intrinsics.checkNotNullParameter("USER_TOKEN", "key");
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
        editor.putString("USER_TOKEN", value);
        editor.commit();
    }

    /* renamed from: j */
    public static final void m4189j(@NotNull UserInfoBean userInfoBean) {
        Intrinsics.checkNotNullParameter(userInfoBean, "<set-?>");
        f9892g = userInfoBean;
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x00fe  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x012a  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0148 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:61:0x015e A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @Override // p005b.p327w.p330b.p331b.ApplicationC2828a, android.app.Application
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onCreate() {
        /*
            Method dump skipped, instructions count: 608
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.MyApp.onCreate():void");
    }

    @Override // android.app.Application, android.content.ComponentCallbacks
    public void onLowMemory() {
        super.onLowMemory();
        ComponentCallbacks2C1553c.m735d(this).m741c();
    }

    @Override // android.app.Application, android.content.ComponentCallbacks2
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        if (level == 20) {
            ComponentCallbacks2C1553c.m735d(this).m742g(level);
        }
    }
}
