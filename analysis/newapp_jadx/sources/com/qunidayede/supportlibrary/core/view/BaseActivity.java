package com.qunidayede.supportlibrary.core.view;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.LocaleList;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.NotificationCompat;
import com.alibaba.fastjson.asm.Opcodes;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.qunidayede.supportlibrary.R$id;
import java.util.Locale;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.TypeCastException;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p190k.p191a.p192a.C1882c;
import p005b.p190k.p191a.p192a.InterfaceC1881b;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p308r.p309a.C2727e;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p331b.p334e.InterfaceC2847j;
import p005b.p327w.p330b.p337d.C2861e;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p381a.C2964m;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

@InterfaceC1881b(edge = InterfaceC1881b.a.LEFT, layout = InterfaceC1881b.c.PARALLAX)
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000v\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\b\b'\u0018\u00002\u00020\u00012\u00020\u0002B\u0007¢\u0006\u0004\bI\u0010\nJ\u0019\u0010\u0006\u001a\u00020\u00052\b\u0010\u0004\u001a\u0004\u0018\u00010\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\bH\u0002¢\u0006\u0004\b\t\u0010\nJ\u0019\u0010\r\u001a\u00020\b2\b\u0010\f\u001a\u0004\u0018\u00010\u000bH\u0014¢\u0006\u0004\b\r\u0010\u000eJ\u0019\u0010\u0011\u001a\u00020\b2\b\u0010\u0010\u001a\u0004\u0018\u00010\u000fH\u0014¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\bH\u0016¢\u0006\u0004\b\u0013\u0010\nJ\u000f\u0010\u0014\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J\u000f\u0010\u0017\u001a\u00020\u0016H\u0016¢\u0006\u0004\b\u0017\u0010\u0018J\u0017\u0010\u001a\u001a\u00020\b2\u0006\u0010\u0019\u001a\u00020\u0016H\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ\u0017\u0010\u001c\u001a\u00020\b2\u0006\u0010\u0019\u001a\u00020\u0016H\u0016¢\u0006\u0004\b\u001c\u0010\u001bJ\u000f\u0010\u001e\u001a\u00020\u001dH\u0016¢\u0006\u0004\b\u001e\u0010\u001fJ\u000f\u0010 \u001a\u00020\u001dH\u0016¢\u0006\u0004\b \u0010\u001fJ\u001d\u0010#\u001a\u00020\b2\f\u0010\"\u001a\b\u0012\u0004\u0012\u00020\b0!H\u0016¢\u0006\u0004\b#\u0010$J\u000f\u0010%\u001a\u00020\bH\u0016¢\u0006\u0004\b%\u0010\nJ\u000f\u0010&\u001a\u00020\bH\u0016¢\u0006\u0004\b&\u0010\nJ\u000f\u0010(\u001a\u00020'H\u0016¢\u0006\u0004\b(\u0010)J\u000f\u0010*\u001a\u00020\u0016H\u0016¢\u0006\u0004\b*\u0010\u0018J\u0019\u0010-\u001a\u00020\u00052\b\u0010,\u001a\u0004\u0018\u00010+H\u0016¢\u0006\u0004\b-\u0010.J\u001f\u00102\u001a\u00020\u00052\b\u00100\u001a\u0004\u0018\u00010/2\u0006\u00101\u001a\u00020+¢\u0006\u0004\b2\u00103J\u000f\u00104\u001a\u00020\bH\u0014¢\u0006\u0004\b4\u0010\nJ\u000f\u00105\u001a\u00020\bH\u0016¢\u0006\u0004\b5\u0010\nJ!\u00108\u001a\u00020\b2\b\b\u0002\u00106\u001a\u00020\u00162\b\b\u0002\u00107\u001a\u00020\u0005¢\u0006\u0004\b8\u00109J\r\u0010:\u001a\u00020\b¢\u0006\u0004\b:\u0010\nJ%\u0010>\u001a\u00020\b2\u0016\u0010=\u001a\f\u0012\b\b\u0001\u0012\u0004\u0018\u00010<0;\"\u0004\u0018\u00010<¢\u0006\u0004\b>\u0010?R\u0018\u0010@\u001a\u0004\u0018\u00010<8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b@\u0010AR%\u0010H\u001a\n C*\u0004\u0018\u00010B0B8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bD\u0010E\u001a\u0004\bF\u0010G¨\u0006J"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "Landroidx/appcompat/app/AppCompatActivity;", "Lb/w/b/b/e/j;", "Landroid/os/IBinder;", "token", "", "hideKeyboard", "(Landroid/os/IBinder;)Z", "", "initTitleBar", "()V", "Landroid/content/Context;", "newBase", "attachBaseContext", "(Landroid/content/Context;)V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "initStatusBar", "initTopBar", "()Z", "", "getRightTitle", "()Ljava/lang/String;", VideoListActivity.KEY_TITLE, "setTitle", "(Ljava/lang/String;)V", "setRightTitle", "Landroid/view/ViewGroup;", "getRightTitleView", "()Landroid/view/ViewGroup;", "getTitleLayout", "Lkotlin/Function0;", "back", "resetBackClick", "(Lkotlin/jvm/functions/Function0;)V", "clickRight", "clickRightIcon", "", "getRightIconRes", "()I", "getTopBarTitle", "Landroid/view/MotionEvent;", "ev", "dispatchTouchEvent", "(Landroid/view/MotionEvent;)Z", "Landroid/view/View;", "v", NotificationCompat.CATEGORY_EVENT, "isShouldHideKeyboard", "(Landroid/view/View;Landroid/view/MotionEvent;)Z", "onPause", "releaseResources", NotificationCompat.CATEGORY_MESSAGE, "now", "showLoadingDialog", "(Ljava/lang/String;Z)V", "hideLoadingDialog", "", "Lc/a/d1;", "jobs", "cancelJob", "([Lkotlinx/coroutines/Job;)V", "loadingJob", "Lc/a/d1;", "Lb/r/a/e;", "kotlin.jvm.PlatformType", "hud$delegate", "Lkotlin/Lazy;", "getHud", "()Lb/r/a/e;", "hud", "<init>", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseActivity extends AppCompatActivity implements InterfaceC2847j {

    /* renamed from: hud$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy hud = LazyKt__LazyJVMKt.lazy(new C4033b());

    @Nullable
    private InterfaceC3053d1 loadingJob;

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseActivity$a */
    /* loaded from: classes.dex */
    public static final class C4032a extends Lambda implements Function1<View, Unit> {

        /* renamed from: c */
        public final /* synthetic */ int f10304c;

        /* renamed from: e */
        public final /* synthetic */ Object f10305e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4032a(int i2, Object obj) {
            super(1);
            this.f10304c = i2;
            this.f10305e = obj;
        }

        @Override // kotlin.jvm.functions.Function1
        public final Unit invoke(View view) {
            int i2 = this.f10304c;
            if (i2 == 0) {
                ((BaseActivity) this.f10305e).finish();
                return Unit.INSTANCE;
            }
            if (i2 != 1) {
                throw null;
            }
            ((BaseActivity) this.f10305e).clickRightIcon();
            return Unit.INSTANCE;
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseActivity$b */
    public static final class C4033b extends Lambda implements Function0<C2727e> {
        public C4033b() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public C2727e invoke() {
            C2727e c2727e = new C2727e(BaseActivity.this);
            c2727e.m3241b(1);
            c2727e.f7407a.setCancelable(true);
            c2727e.f7407a.setOnCancelListener(null);
            return c2727e;
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseActivity$c */
    public static final class C4034c extends Lambda implements Function1<TextView, Unit> {
        public C4034c() {
            super(1);
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(TextView textView) {
            BaseActivity.this.clickRight();
            return Unit.INSTANCE;
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseActivity$d */
    public static final class C4035d extends Lambda implements Function1<View, Unit> {

        /* renamed from: c */
        public final /* synthetic */ Function0<Unit> f10308c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4035d(Function0<Unit> function0) {
            super(1);
            this.f10308c = function0;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(View view) {
            View it = view;
            Intrinsics.checkNotNullParameter(it, "it");
            this.f10308c.invoke();
            return Unit.INSTANCE;
        }
    }

    @DebugMetadata(m5319c = "com.qunidayede.supportlibrary.core.view.BaseActivity$showLoadingDialog$1", m5320f = "BaseActivity.kt", m5321i = {}, m5322l = {Opcodes.CHECKCAST}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseActivity$e */
    public static final class C4036e extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {

        /* renamed from: c */
        public int f10309c;

        public C4036e(Continuation<? super C4036e> continuation) {
            super(2, continuation);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return BaseActivity.this.new C4036e(continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        public Object invoke(InterfaceC3055e0 interfaceC3055e0, Continuation<? super Unit> continuation) {
            return BaseActivity.this.new C4036e(continuation).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            int i2 = this.f10309c;
            if (i2 == 0) {
                ResultKt.throwOnFailure(obj);
                this.f10309c = 1;
                if (C2354n.m2422Q(1500L, this) == coroutine_suspended) {
                    return coroutine_suspended;
                }
            } else {
                if (i2 != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                ResultKt.throwOnFailure(obj);
            }
            C2727e hud = BaseActivity.this.getHud();
            if (!hud.m3240a()) {
                hud.f7412f = false;
                hud.f7407a.show();
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final C2727e getHud() {
        return (C2727e) this.hud.getValue();
    }

    private final boolean hideKeyboard(IBinder token) {
        if (token == null) {
            return false;
        }
        Object systemService = getSystemService("input_method");
        Objects.requireNonNull(systemService, "null cannot be cast to non-null type android.view.inputmethod.InputMethodManager");
        return ((InputMethodManager) systemService).hideSoftInputFromWindow(token, 2);
    }

    private final void initTitleBar() {
        if (initTopBar()) {
            int i2 = R$id.title_layout;
            if (findViewById(i2) != null) {
                int statusBarHeight = ImmersionBar.getStatusBarHeight(this);
                View findViewById = findViewById(i2);
                Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById<ViewGroup>(R.id.title_layout)");
                ViewGroup.LayoutParams layoutParams = findViewById.getLayoutParams();
                if (layoutParams == null) {
                    throw new TypeCastException("null cannot be cast to non-null type android.view.ViewGroup.LayoutParams");
                }
                layoutParams.height = C2354n.m2425R(this, 45.0f) + statusBarHeight;
                findViewById.setLayoutParams(layoutParams);
                View findViewById2 = findViewById(i2);
                Intrinsics.checkNotNullExpressionValue(findViewById2, "findViewById<ViewGroup>(R.id.title_layout)");
                findViewById2.setPadding(findViewById2.getPaddingLeft(), statusBarHeight, findViewById2.getPaddingRight(), findViewById2.getPaddingBottom());
            }
            int i3 = R$id.tv_title;
            if (findViewById(i3) != null) {
                int i4 = R$id.btn_titleBack;
                if (findViewById(i4) != null) {
                    ((TextView) findViewById(i3)).setText(getTopBarTitle());
                    C2354n.m2380C(findViewById(i4), 200L, new C4032a(0, this));
                }
            }
            int i5 = R$id.tv_titleRight;
            if (findViewById(i5) != null) {
                ((TextView) findViewById(i5)).setText(getRightTitle());
                C2354n.m2380C(findViewById(i5), 200L, new C4034c());
            }
            int i6 = R$id.iv_titleRightIcon;
            if (findViewById(i6) != null) {
                int i7 = R$id.btn_titleRightIcon;
                if (findViewById(i7) != null) {
                    int rightIconRes = getRightIconRes();
                    if (rightIconRes <= 0) {
                        findViewById(i7).setVisibility(8);
                        return;
                    }
                    findViewById(i7).setVisibility(0);
                    ((ImageView) findViewById(i6)).setImageResource(rightIconRes);
                    C2354n.m2380C(findViewById(i7), 200L, new C4032a(1, this));
                }
            }
        }
    }

    public static /* synthetic */ void showLoadingDialog$default(BaseActivity baseActivity, String str, boolean z, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: showLoadingDialog");
        }
        if ((i2 & 1) != 0) {
            str = "loading...";
        }
        if ((i2 & 2) != 0) {
            z = false;
        }
        baseActivity.showLoadingDialog(str, z);
    }

    public void _$_clearFindViewByIdCache() {
    }

    @Override // androidx.appcompat.app.AppCompatActivity, android.app.Activity, android.view.ContextThemeWrapper, android.content.ContextWrapper
    public void attachBaseContext(@Nullable Context newBase) {
        Intrinsics.checkNotNullParameter(IjkMediaMeta.IJKM_KEY_LANGUAGE, "key");
        Intrinsics.checkNotNullParameter("CHINESE", "default");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        String language = sharedPreferences.getString(IjkMediaMeta.IJKM_KEY_LANGUAGE, "CHINESE");
        Intrinsics.checkNotNull(language);
        Intrinsics.checkNotNull(newBase);
        Intrinsics.checkNotNullParameter(newBase, "context");
        Intrinsics.checkNotNullParameter(language, "language");
        if (Build.VERSION.SDK_INT >= 24) {
            Resources resources = newBase.getResources();
            Locale locale = Locale.SIMPLIFIED_CHINESE;
            if (Intrinsics.areEqual(language, "zh")) {
                locale = Locale.SIMPLIFIED_CHINESE;
            } else if (Intrinsics.areEqual(language, "en")) {
                locale = Locale.ENGLISH;
            }
            Intrinsics.checkNotNullExpressionValue(locale, "locale");
            Configuration configuration = resources.getConfiguration();
            configuration.setLocale(locale);
            configuration.setLocales(new LocaleList(locale));
            Intrinsics.checkNotNullExpressionValue(newBase.createConfigurationContext(configuration), "context.createConfigurationContext(configuration)");
        }
        super.attachBaseContext(newBase);
    }

    public final void cancelJob(@NotNull InterfaceC3053d1... jobs) {
        Intrinsics.checkNotNullParameter(jobs, "jobs");
        for (InterfaceC3053d1 interfaceC3053d1 : jobs) {
            if (interfaceC3053d1 != null && interfaceC3053d1.mo3507b()) {
                C2354n.m2512s(interfaceC3053d1, null, 1, null);
            }
        }
    }

    public void clickRight() {
    }

    public void clickRightIcon() {
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean dispatchTouchEvent(@Nullable MotionEvent ev) {
        Integer valueOf = ev == null ? null : Integer.valueOf(ev.getAction());
        if (valueOf != null && valueOf.intValue() == 0) {
            View currentFocus = getCurrentFocus();
            if (isShouldHideKeyboard(currentFocus, ev)) {
                if (hideKeyboard(currentFocus != null ? currentFocus.getWindowToken() : null)) {
                    return true;
                }
            }
        }
        return super.dispatchTouchEvent(ev);
    }

    public int getRightIconRes() {
        return 0;
    }

    @NotNull
    public String getRightTitle() {
        return "";
    }

    @NotNull
    public ViewGroup getRightTitleView() {
        View findViewById = findViewById(R$id.btn_titleRight);
        Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.view.ViewGroup");
        return (ViewGroup) findViewById;
    }

    @NotNull
    public ViewGroup getTitleLayout() {
        View findViewById = findViewById(R$id.title_layout);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(R.id.title_layout)");
        return (ViewGroup) findViewById;
    }

    @NotNull
    public String getTopBarTitle() {
        return "";
    }

    public final void hideLoadingDialog() {
        C2727e.a aVar;
        if (getHud().m3240a()) {
            C2727e hud = getHud();
            hud.f7412f = true;
            Context context = hud.f7410d;
            if (context != null && !((Activity) context).isFinishing() && (aVar = hud.f7407a) != null && aVar.isShowing()) {
                hud.f7407a.dismiss();
            }
        }
        cancelJob(this.loadingJob);
    }

    public void initStatusBar() {
        ImmersionBar.with(this).fitsSystemWindows(false).navigationBarColor("#00000000").statusBarDarkFont(true).init();
    }

    public boolean initTopBar() {
        return true;
    }

    public final boolean isShouldHideKeyboard(@Nullable View v, @NotNull MotionEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (v == null || !(v instanceof EditText)) {
            return false;
        }
        int[] iArr = {0, 0};
        EditText editText = (EditText) v;
        editText.getLocationInWindow(iArr);
        int i2 = iArr[0];
        int i3 = iArr[1];
        return event.getX() <= ((float) i2) || event.getX() >= ((float) (editText.getWidth() + i2)) || event.getY() <= ((float) i3) || event.getY() >= ((float) (editText.getHeight() + i3));
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setSoftInputMode(32);
        C1882c.m1213a(this, true).setEdgeMode(1);
        initStatusBar();
        setContentView(getLayoutId());
        initTitleBar();
        bindEvent();
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onPause() {
        super.onPause();
        View currentFocus = getCurrentFocus();
        if (currentFocus == null) {
            View decorView = getWindow().getDecorView();
            View findViewWithTag = decorView.findViewWithTag("keyboardTagView");
            if (findViewWithTag == null) {
                findViewWithTag = new EditText(this);
                findViewWithTag.setTag("keyboardTagView");
                ((ViewGroup) decorView).addView(findViewWithTag, 0, 0);
            }
            currentFocus = findViewWithTag;
            currentFocus.requestFocus();
        }
        C2861e.m3306d(currentFocus);
        if (isFinishing()) {
            releaseResources();
        }
    }

    public void releaseResources() {
        hideLoadingDialog();
    }

    public void resetBackClick(@NotNull Function0<Unit> back) {
        Intrinsics.checkNotNullParameter(back, "back");
        View findViewById = findViewById(R$id.btn_titleBack);
        if (findViewById == null) {
            return;
        }
        C2354n.m2380C(findViewById, 2000L, new C4035d(back));
    }

    public void setRightTitle(@NotNull String title) {
        Intrinsics.checkNotNullParameter(title, "title");
        TextView textView = (TextView) findViewById(R$id.tv_titleRight);
        if (textView == null) {
            return;
        }
        textView.setText(title);
    }

    public void setTitle(@NotNull String title) {
        Intrinsics.checkNotNullParameter(title, "title");
        TextView textView = (TextView) findViewById(R$id.tv_title);
        if (textView == null) {
            return;
        }
        textView.setText(title);
    }

    public boolean showHomeAsUp() {
        Intrinsics.checkNotNullParameter(this, "this");
        return false;
    }

    public final void showLoadingDialog(@NotNull String msg, boolean now) {
        Intrinsics.checkNotNullParameter(msg, "msg");
        C2727e.a aVar = getHud().f7407a;
        aVar.f7418i = msg;
        TextView textView = aVar.f7416g;
        if (textView != null) {
            if (msg != null) {
                textView.setText(msg);
                aVar.f7416g.setVisibility(0);
            } else {
                textView.setVisibility(8);
            }
        }
        if (getHud().m3240a()) {
            return;
        }
        if (!now) {
            cancelJob(this.loadingJob);
            C3109w0 c3109w0 = C3109w0.f8471c;
            C3079m0 c3079m0 = C3079m0.f8432c;
            this.loadingJob = C2354n.m2435U0(c3109w0, C2964m.f8127b, 0, new C4036e(null), 2, null);
            return;
        }
        C2727e hud = getHud();
        if (hud.m3240a()) {
            return;
        }
        hud.f7412f = false;
        hud.f7407a.show();
    }
}
