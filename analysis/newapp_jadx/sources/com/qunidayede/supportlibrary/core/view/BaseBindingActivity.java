package com.qunidayede.supportlibrary.core.view;

import android.annotation.SuppressLint;
import android.content.Intent;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStub;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.CallSuper;
import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.content.ContextCompat;
import androidx.core.widget.ImageViewCompat;
import androidx.lifecycle.LifecycleCoroutineScope;
import androidx.lifecycle.LifecycleOwnerKt;
import androidx.viewbinding.ViewBinding;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.qunidayede.supportlibrary.R$color;
import com.qunidayede.supportlibrary.R$id;
import com.qunidayede.supportlibrary.core.view.BaseBindingActivity;
import com.qunidayede.supportlibrary.databinding.LayoutNetworkErrorBinding;
import com.qunidayede.supportlibrary.databinding.TitleBarLayoutBinding;
import com.qunidayede.supportlibrary.databinding.ViewRootBinding;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p190k.p191a.p192a.InterfaceC1881b;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p332c.C2831b;
import p005b.p327w.p330b.p331b.p334e.InterfaceC2846i;
import p005b.p327w.p330b.p331b.p334e.InterfaceC2847j;
import p426f.p427a.p428a.C4325a;

@InterfaceC1881b(edge = InterfaceC1881b.a.LEFT, layout = InterfaceC1881b.c.PARALLAX)
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0098\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0003\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u001b\n\u0002\u0018\u0002\n\u0002\b\u0006\b'\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u00012\u00020\u00032\u00020\u00042\u00020\u00052\u00020\u0006B\u0007¢\u0006\u0004\bh\u0010\fJ\r\u0010\b\u001a\u00020\u0007¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fJ\r\u0010\u000e\u001a\u00020\r¢\u0006\u0004\b\u000e\u0010\u000fJ\u001d\u0010\u0013\u001a\u00020\n*\u00020\u00102\b\b\u0002\u0010\u0012\u001a\u00020\u0011H\u0007¢\u0006\u0004\b\u0013\u0010\u0014J8\u0010\u0019\u001a\u00020\n\"\n\b\u0001\u0010\u0015\u0018\u0001*\u00020\u00012\u0017\u0010\u0018\u001a\u0013\u0012\u0004\u0012\u00028\u0001\u0012\u0004\u0012\u00020\n0\u0016¢\u0006\u0002\b\u0017H\u0086\bø\u0001\u0000¢\u0006\u0004\b\u0019\u0010\u001aJ\u0011\u0010\u001b\u001a\u0004\u0018\u00010\u0001H\u0016¢\u0006\u0004\b\u001b\u0010\u001cJ\u000f\u0010\u001e\u001a\u00020\u001dH\u0016¢\u0006\u0004\b\u001e\u0010\u001fJ\u000f\u0010 \u001a\u00020\nH\u0016¢\u0006\u0004\b \u0010\fJ\u000f\u0010!\u001a\u00020\nH\u0016¢\u0006\u0004\b!\u0010\fJ(\u0010\"\u001a\u00020\n2\u0017\u0010\u0018\u001a\u0013\u0012\u0004\u0012\u00020\r\u0012\u0004\u0012\u00020\n0\u0016¢\u0006\u0002\b\u0017H\u0016¢\u0006\u0004\b\"\u0010\u001aJ(\u0010#\u001a\u00020\n2\u0017\u0010\u0018\u001a\u0013\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\n0\u0016¢\u0006\u0002\b\u0017H\u0016¢\u0006\u0004\b#\u0010\u001aJ(\u0010%\u001a\u00020\n2\u0017\u0010\u0018\u001a\u0013\u0012\u0004\u0012\u00020$\u0012\u0004\u0012\u00020\n0\u0016¢\u0006\u0002\b\u0017H\u0016¢\u0006\u0004\b%\u0010\u001aJ\u0019\u0010(\u001a\u00020\n2\b\u0010'\u001a\u0004\u0018\u00010&H\u0015¢\u0006\u0004\b(\u0010)J\u0019\u0010,\u001a\u00020\n2\b\u0010+\u001a\u0004\u0018\u00010*H\u0015¢\u0006\u0004\b,\u0010-J\u0019\u0010/\u001a\u00020\n2\b\u0010.\u001a\u0004\u0018\u00010\u0010H\u0016¢\u0006\u0004\b/\u00100J\u0017\u00103\u001a\u00020\n2\u0006\u00102\u001a\u000201H\u0016¢\u0006\u0004\b3\u00104J\u0017\u00105\u001a\u00020\n2\u0006\u00102\u001a\u000201H\u0016¢\u0006\u0004\b5\u00104J\u000f\u00107\u001a\u000206H\u0016¢\u0006\u0004\b7\u00108J\u000f\u00109\u001a\u00020\nH\u0016¢\u0006\u0004\b9\u0010\fJ\u000f\u0010:\u001a\u00020\nH\u0016¢\u0006\u0004\b:\u0010\fJ\u000f\u0010;\u001a\u00020\nH\u0016¢\u0006\u0004\b;\u0010\fJ\u0017\u0010>\u001a\u00020\n2\u0006\u0010=\u001a\u00020<H\u0016¢\u0006\u0004\b>\u0010?J\u000f\u0010@\u001a\u00020\nH\u0016¢\u0006\u0004\b@\u0010\fJ\u000f\u0010B\u001a\u00020AH\u0016¢\u0006\u0004\bB\u0010CJ\u000f\u0010D\u001a\u000201H\u0016¢\u0006\u0004\bD\u0010EJ\u000f\u0010F\u001a\u000206H\u0016¢\u0006\u0004\bF\u00108J\u001d\u0010I\u001a\u00020\n2\f\u0010H\u001a\b\u0012\u0004\u0012\u00020\n0GH\u0016¢\u0006\u0004\bI\u0010JJ\u000f\u0010K\u001a\u00020\nH\u0016¢\u0006\u0004\bK\u0010\fJ\u000f\u0010L\u001a\u00020\nH\u0016¢\u0006\u0004\bL\u0010\fJ\u000f\u0010M\u001a\u00020\u0007H\u0016¢\u0006\u0004\bM\u0010\tJ\u000f\u0010N\u001a\u000201H\u0016¢\u0006\u0004\bN\u0010EJ\u000f\u0010O\u001a\u00020\nH\u0016¢\u0006\u0004\bO\u0010\fJ\u000f\u0010P\u001a\u00020\nH\u0016¢\u0006\u0004\bP\u0010\fJ\u000f\u0010Q\u001a\u00020AH\u0016¢\u0006\u0004\bQ\u0010CJ\u000f\u0010R\u001a\u00020AH\u0016¢\u0006\u0004\bR\u0010CJ\u000f\u0010S\u001a\u00020\u0007H\u0016¢\u0006\u0004\bS\u0010\tJ\u0019\u0010U\u001a\u00020\n2\b\b\u0002\u0010T\u001a\u00020AH\u0002¢\u0006\u0004\bU\u0010VR\u001d\u0010\"\u001a\u00020\r8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bW\u0010X\u001a\u0004\bY\u0010\u000fR\u001d\u0010#\u001a\u00028\u00008D@\u0004X\u0084\u0084\u0002¢\u0006\f\n\u0004\bZ\u0010X\u001a\u0004\b[\u0010\u001cR\u0018\u0010\u0019\u001a\u0004\u0018\u00010\u00018\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0019\u0010\\R$\u0010]\u001a\u0004\u0018\u00010$8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b]\u0010^\u001a\u0004\b_\u0010`\"\u0004\ba\u0010bR\u001d\u0010g\u001a\u00020c8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bd\u0010X\u001a\u0004\be\u0010f\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006i"}, m5311d2 = {"Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "Landroidx/viewbinding/ViewBinding;", "VB", "Landroidx/appcompat/app/AppCompatActivity;", "Lb/w/b/b/e/i;", "Lb/w/b/b/e/j;", "", "", "getLayoutId", "()I", "", "releaseResources", "()V", "Lcom/qunidayede/supportlibrary/databinding/ViewRootBinding;", "getRootBanding", "()Lcom/qunidayede/supportlibrary/databinding/ViewRootBinding;", "Landroid/view/View;", "", "pressedAlpha", "fadeWhenTouch", "(Landroid/view/View;F)V", "FVB", "Lkotlin/Function1;", "Lkotlin/ExtensionFunctionType;", "block", "failedBinding", "(Lkotlin/jvm/functions/Function1;)V", "getFailedBinding", "()Landroidx/viewbinding/ViewBinding;", "Landroidx/lifecycle/LifecycleCoroutineScope;", "scope", "()Landroidx/lifecycle/LifecycleCoroutineScope;", "showFailedView", "removeFailedView", "rootBinding", "bodyBinding", "Lcom/qunidayede/supportlibrary/databinding/TitleBarLayoutBinding;", "titleBinding", "Landroid/content/Intent;", "intent", "onNewIntent", "(Landroid/content/Intent;)V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "view", "setContentView", "(Landroid/view/View;)V", "", VideoListActivity.KEY_TITLE, "setTitle", "(Ljava/lang/String;)V", "setRightTitle", "Landroid/view/ViewGroup;", "getRightTitleView", "()Landroid/view/ViewGroup;", "loadingDialog", "loadingView", "hideLoading", "", "t", "onError", "(Ljava/lang/Throwable;)V", "initStatusBar", "", "initTopBar", "()Z", "getRightTitle", "()Ljava/lang/String;", "getTitleLayout", "Lkotlin/Function0;", "back", "resetBackClick", "(Lkotlin/jvm/functions/Function0;)V", "clickRight", "clickRightIcon", "getRightIconRes", "getTopBarTitle", "bindEvent", "initView", "immersionBar", "contentOverlay", "backColor", "showNow", "inflateTitleBar", "(Z)V", "rootBinding$delegate", "Lkotlin/Lazy;", "getRootBinding", "bodyBinding$delegate", "getBodyBinding", "Landroidx/viewbinding/ViewBinding;", "titleBarBinding", "Lcom/qunidayede/supportlibrary/databinding/TitleBarLayoutBinding;", "getTitleBarBinding", "()Lcom/qunidayede/supportlibrary/databinding/TitleBarLayoutBinding;", "setTitleBarBinding", "(Lcom/qunidayede/supportlibrary/databinding/TitleBarLayoutBinding;)V", "Lb/w/b/b/c/b;", "loadingViewController$delegate", "getLoadingViewController", "()Lb/w/b/b/c/b;", "loadingViewController", "<init>", "library_support_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class BaseBindingActivity<VB extends ViewBinding> extends AppCompatActivity implements InterfaceC2846i, InterfaceC2847j {

    @Nullable
    private ViewBinding failedBinding;

    @Nullable
    private TitleBarLayoutBinding titleBarBinding;

    /* renamed from: bodyBinding$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy bodyBinding = LazyKt__LazyJVMKt.lazy(new C4037a(this));

    /* renamed from: rootBinding$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rootBinding = LazyKt__LazyJVMKt.lazy(new C4045i(this));

    /* renamed from: loadingViewController$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy loadingViewController = LazyKt__LazyJVMKt.lazy(new C4042f(this));

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseBindingActivity$a */
    public static final class C4037a extends Lambda implements Function0<VB> {

        /* renamed from: c */
        public final /* synthetic */ BaseBindingActivity<VB> f10311c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4037a(BaseBindingActivity<VB> baseBindingActivity) {
            super(0);
            this.f10311c = baseBindingActivity;
        }

        @Override // kotlin.jvm.functions.Function0
        public Object invoke() {
            Type genericSuperclass = this.f10311c.getClass().getGenericSuperclass();
            Objects.requireNonNull(genericSuperclass, "null cannot be cast to non-null type java.lang.reflect.ParameterizedType");
            Type type = ((ParameterizedType) genericSuperclass).getActualTypeArguments()[0];
            Objects.requireNonNull(type, "null cannot be cast to non-null type java.lang.Class<VB of com.qunidayede.supportlibrary.core.view.BaseBindingActivity>");
            Method declaredMethod = ((Class) type).getDeclaredMethod("inflate", LayoutInflater.class);
            BaseBindingActivity<VB> baseBindingActivity = this.f10311c;
            Object invoke = declaredMethod.invoke(baseBindingActivity, baseBindingActivity.getLayoutInflater());
            Objects.requireNonNull(invoke, "null cannot be cast to non-null type VB of com.qunidayede.supportlibrary.core.view.BaseBindingActivity");
            return (ViewBinding) invoke;
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseBindingActivity$b */
    public static final class ViewOnLayoutChangeListenerC4038b implements View.OnLayoutChangeListener {

        /* renamed from: c */
        public final /* synthetic */ BaseBindingActivity<VB> f10312c;

        /* renamed from: e */
        public final /* synthetic */ View f10313e;

        public ViewOnLayoutChangeListenerC4038b(BaseBindingActivity<VB> baseBindingActivity, View view) {
            this.f10312c = baseBindingActivity;
            this.f10313e = view;
        }

        @Override // android.view.View.OnLayoutChangeListener
        public void onLayoutChange(@Nullable View view, int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9) {
            int i10 = i5 - i3;
            if (i10 != 0) {
                if (!this.f10312c.immersionBar()) {
                    View root = this.f10312c.getBodyBinding().getRoot();
                    Intrinsics.checkNotNullExpressionValue(root, "bodyBinding.root");
                    ViewGroup.LayoutParams layoutParams = root.getLayoutParams();
                    if (layoutParams == null) {
                        throw new TypeCastException("null cannot be cast to non-null type android.view.ViewGroup.LayoutParams");
                    }
                    if (layoutParams instanceof ViewGroup.MarginLayoutParams) {
                        ((ViewGroup.MarginLayoutParams) layoutParams).topMargin = i10;
                    }
                    root.setLayoutParams(layoutParams);
                }
                this.f10313e.removeOnLayoutChangeListener(this);
            }
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseBindingActivity$c */
    public static final class C4039c extends Lambda implements Function1<FrameLayout, Unit> {

        /* renamed from: c */
        public final /* synthetic */ BaseBindingActivity<VB> f10314c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4039c(BaseBindingActivity<VB> baseBindingActivity) {
            super(1);
            this.f10314c = baseBindingActivity;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(FrameLayout frameLayout) {
            FrameLayout it = frameLayout;
            Intrinsics.checkNotNullParameter(it, "it");
            this.f10314c.finish();
            return Unit.INSTANCE;
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseBindingActivity$d */
    public static final class C4040d extends Lambda implements Function1<ImageView, Unit> {

        /* renamed from: c */
        public final /* synthetic */ BaseBindingActivity<VB> f10315c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4040d(BaseBindingActivity<VB> baseBindingActivity) {
            super(1);
            this.f10315c = baseBindingActivity;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(ImageView imageView) {
            ImageView it = imageView;
            Intrinsics.checkNotNullParameter(it, "it");
            this.f10315c.clickRightIcon();
            return Unit.INSTANCE;
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseBindingActivity$e */
    public static final class C4041e extends Lambda implements Function1<TextView, Unit> {

        /* renamed from: c */
        public final /* synthetic */ BaseBindingActivity<VB> f10316c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4041e(BaseBindingActivity<VB> baseBindingActivity) {
            super(1);
            this.f10316c = baseBindingActivity;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(TextView textView) {
            TextView it = textView;
            Intrinsics.checkNotNullParameter(it, "it");
            this.f10316c.clickRight();
            return Unit.INSTANCE;
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseBindingActivity$f */
    public static final class C4042f extends Lambda implements Function0<C2831b> {

        /* renamed from: c */
        public final /* synthetic */ BaseBindingActivity<VB> f10317c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4042f(BaseBindingActivity<VB> baseBindingActivity) {
            super(0);
            this.f10317c = baseBindingActivity;
        }

        @Override // kotlin.jvm.functions.Function0
        public C2831b invoke() {
            BaseBindingActivity<VB> baseBindingActivity = this.f10317c;
            return new C2831b(baseBindingActivity, baseBindingActivity.getRootBinding());
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseBindingActivity$g */
    public static final class C4043g extends Lambda implements Function1<ViewRootBinding, Unit> {

        /* renamed from: c */
        public final /* synthetic */ ViewBinding f10318c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4043g(ViewBinding viewBinding) {
            super(1);
            this.f10318c = viewBinding;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(ViewRootBinding viewRootBinding) {
            ViewRootBinding rootBinding = viewRootBinding;
            Intrinsics.checkNotNullParameter(rootBinding, "$this$rootBinding");
            FrameLayout layoutBody = rootBinding.layoutBody;
            Intrinsics.checkNotNullExpressionValue(layoutBody, "layoutBody");
            View root = this.f10318c.getRoot();
            Intrinsics.checkNotNullExpressionValue(root, "it.root");
            if (layoutBody.indexOfChild(root) != -1) {
                rootBinding.layoutBody.removeView(this.f10318c.getRoot());
            }
            return Unit.INSTANCE;
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseBindingActivity$h */
    public static final class C4044h extends Lambda implements Function1<FrameLayout, Unit> {

        /* renamed from: c */
        public final /* synthetic */ Function0<Unit> f10319c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4044h(Function0<Unit> function0) {
            super(1);
            this.f10319c = function0;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(FrameLayout frameLayout) {
            FrameLayout it = frameLayout;
            Intrinsics.checkNotNullParameter(it, "it");
            this.f10319c.invoke();
            return Unit.INSTANCE;
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseBindingActivity$i */
    public static final class C4045i extends Lambda implements Function0<ViewRootBinding> {

        /* renamed from: c */
        public final /* synthetic */ BaseBindingActivity<VB> f10320c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4045i(BaseBindingActivity<VB> baseBindingActivity) {
            super(0);
            this.f10320c = baseBindingActivity;
        }

        @Override // kotlin.jvm.functions.Function0
        public ViewRootBinding invoke() {
            ViewRootBinding inflate = ViewRootBinding.inflate(this.f10320c.getLayoutInflater());
            Intrinsics.checkNotNullExpressionValue(inflate, "inflate(layoutInflater)");
            return inflate;
        }
    }

    /* renamed from: com.qunidayede.supportlibrary.core.view.BaseBindingActivity$j */
    public static final class C4046j extends Lambda implements Function1<ViewRootBinding, Unit> {

        /* renamed from: c */
        public final /* synthetic */ ViewBinding f10321c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C4046j(ViewBinding viewBinding) {
            super(1);
            this.f10321c = viewBinding;
        }

        @Override // kotlin.jvm.functions.Function1
        public Unit invoke(ViewRootBinding viewRootBinding) {
            ViewRootBinding rootBinding = viewRootBinding;
            Intrinsics.checkNotNullParameter(rootBinding, "$this$rootBinding");
            FrameLayout layoutBody = rootBinding.layoutBody;
            Intrinsics.checkNotNullExpressionValue(layoutBody, "layoutBody");
            View root = this.f10321c.getRoot();
            Intrinsics.checkNotNullExpressionValue(root, "it.root");
            if (!(layoutBody.indexOfChild(root) != -1)) {
                rootBinding.layoutBody.addView(this.f10321c.getRoot());
            }
            return Unit.INSTANCE;
        }
    }

    public static /* synthetic */ void fadeWhenTouch$default(BaseBindingActivity baseBindingActivity, View view, float f2, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: fadeWhenTouch");
        }
        if ((i2 & 1) != 0) {
            f2 = 0.5f;
        }
        baseBindingActivity.fadeWhenTouch(view, f2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: fadeWhenTouch$lambda-0, reason: not valid java name */
    public static final boolean m6043fadeWhenTouch$lambda0(float f2, View view, MotionEvent motionEvent) {
        Integer valueOf = motionEvent == null ? null : Integer.valueOf(motionEvent.getAction());
        if (valueOf != null && valueOf.intValue() == 0) {
            if (view == null) {
                return false;
            }
            view.setAlpha(f2);
            return false;
        }
        if (valueOf != null && valueOf.intValue() == 1) {
            if (view == null) {
                return false;
            }
            view.setAlpha(1.0f);
            return false;
        }
        if (valueOf == null || valueOf.intValue() != 3 || view == null) {
            return false;
        }
        view.setAlpha(1.0f);
        return false;
    }

    private final C2831b getLoadingViewController() {
        return (C2831b) this.loadingViewController.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ViewRootBinding getRootBinding() {
        return (ViewRootBinding) this.rootBinding.getValue();
    }

    private final void inflateTitleBar(final boolean showNow) {
        ViewStub viewStub;
        try {
            viewStub = (ViewStub) findViewById(R$id.title_bar_view_stub);
        } catch (Exception unused) {
            viewStub = null;
        }
        if (viewStub != null) {
            viewStub.setOnInflateListener(new ViewStub.OnInflateListener() { // from class: b.w.b.b.e.a
                @Override // android.view.ViewStub.OnInflateListener
                public final void onInflate(ViewStub viewStub2, View view) {
                    BaseBindingActivity.m6044inflateTitleBar$lambda7(BaseBindingActivity.this, showNow, viewStub2, view);
                }
            });
        }
        if (viewStub == null) {
            return;
        }
        viewStub.inflate();
    }

    public static /* synthetic */ void inflateTitleBar$default(BaseBindingActivity baseBindingActivity, boolean z, int i2, Object obj) {
        if (obj != null) {
            throw new UnsupportedOperationException("Super calls with default arguments not supported in this target, function: inflateTitleBar");
        }
        if ((i2 & 1) != 0) {
            z = false;
        }
        baseBindingActivity.inflateTitleBar(z);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: inflateTitleBar$lambda-7, reason: not valid java name */
    public static final void m6044inflateTitleBar$lambda7(BaseBindingActivity this$0, boolean z, ViewStub viewStub, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ImmersionBar.setTitleBar(this$0, view);
        if (this$0.contentOverlay()) {
            View root = this$0.getBodyBinding().getRoot();
            Intrinsics.checkNotNullExpressionValue(root, "bodyBinding.root");
            ViewGroup.LayoutParams layoutParams = root.getLayoutParams();
            if (layoutParams == null) {
                throw new TypeCastException("null cannot be cast to non-null type android.view.ViewGroup.LayoutParams");
            }
            if (layoutParams instanceof ViewGroup.MarginLayoutParams) {
                ((ViewGroup.MarginLayoutParams) layoutParams).topMargin = ImmersionBar.getStatusBarHeight(this$0);
            }
            root.setLayoutParams(layoutParams);
        } else {
            view.addOnLayoutChangeListener(new ViewOnLayoutChangeListenerC4038b(this$0, view));
        }
        if (this$0.immersionBar()) {
            view.setBackgroundColor(0);
        }
        TitleBarLayoutBinding bind = TitleBarLayoutBinding.bind(view);
        ImageViewCompat.setImageTintList(bind.ivTitleLeftIcon, ContextCompat.getColorStateList(this$0, R$color.black));
        C2354n.m2377B(bind.btnTitleBack, 0L, new C4039c(this$0), 1);
        if (z) {
            bind.tvTitle.setText(this$0.getTopBarTitle());
            bind.tvTitleRight.setText(this$0.getRightTitle());
            if (this$0.getRightIconRes() != -1) {
                bind.ivTitleRightIcon.setImageResource(this$0.getRightIconRes());
            }
            C2354n.m2380C(bind.ivTitleRightIcon, 200L, new C4040d(this$0));
            C2354n.m2380C(bind.tvTitleRight, 200L, new C4041e(this$0));
        }
        Unit unit = Unit.INSTANCE;
        this$0.setTitleBarBinding(bind);
    }

    public void _$_clearFindViewByIdCache() {
    }

    public int backColor() {
        return R$color.black;
    }

    public void bindEvent() {
    }

    public void bodyBinding(@NotNull Function1<? super VB, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        block.invoke(getBodyBinding());
    }

    public void clickRight() {
    }

    public void clickRightIcon() {
    }

    public boolean contentOverlay() {
        return false;
    }

    @SuppressLint({"ClickableViewAccessibility"})
    public final void fadeWhenTouch(@NotNull View view, final float f2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setOnTouchListener(new View.OnTouchListener() { // from class: b.w.b.b.e.b
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view2, MotionEvent motionEvent) {
                boolean m6043fadeWhenTouch$lambda0;
                m6043fadeWhenTouch$lambda0 = BaseBindingActivity.m6043fadeWhenTouch$lambda0(f2, view2, motionEvent);
                return m6043fadeWhenTouch$lambda0;
            }
        });
    }

    public final /* synthetic */ void failedBinding(Function1 block) {
        Intrinsics.checkNotNullParameter(block, "block");
        ViewBinding failedBinding = getFailedBinding();
        if (failedBinding == null) {
            return;
        }
        Intrinsics.reifiedOperationMarker(1, "FVB");
        block.invoke(failedBinding);
    }

    @NotNull
    public final VB getBodyBinding() {
        return (VB) this.bodyBinding.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    @Nullable
    public ViewBinding getFailedBinding() {
        if (this.failedBinding == null) {
            this.failedBinding = LayoutNetworkErrorBinding.inflate(getLayoutInflater());
        }
        return this.failedBinding;
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public final int getLayoutId() {
        return -1;
    }

    public int getRightIconRes() {
        return -1;
    }

    @NotNull
    public String getRightTitle() {
        return "";
    }

    @NotNull
    public ViewGroup getRightTitleView() {
        inflateTitleBar$default(this, false, 1, null);
        TitleBarLayoutBinding titleBarLayoutBinding = this.titleBarBinding;
        Intrinsics.checkNotNull(titleBarLayoutBinding);
        FrameLayout frameLayout = titleBarLayoutBinding.btnTitleRight;
        Intrinsics.checkNotNullExpressionValue(frameLayout, "titleBarBinding!!.btnTitleRight");
        return frameLayout;
    }

    @NotNull
    public final ViewRootBinding getRootBanding() {
        return getRootBinding();
    }

    @Nullable
    public final TitleBarLayoutBinding getTitleBarBinding() {
        return this.titleBarBinding;
    }

    @NotNull
    public ViewGroup getTitleLayout() {
        inflateTitleBar$default(this, false, 1, null);
        TitleBarLayoutBinding titleBarLayoutBinding = this.titleBarBinding;
        Intrinsics.checkNotNull(titleBarLayoutBinding);
        ConstraintLayout root = titleBarLayoutBinding.getRoot();
        Intrinsics.checkNotNullExpressionValue(root, "titleBarBinding!!.root");
        return root;
    }

    @NotNull
    public String getTopBarTitle() {
        return "";
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    public void hideLoading() {
        getLoadingViewController().m3283a();
    }

    public boolean immersionBar() {
        return false;
    }

    public void initStatusBar() {
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.autoStatusBarDarkModeEnable(true, 0.2f);
        with.init();
    }

    public boolean initTopBar() {
        return false;
    }

    public void initView() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    public void loadingDialog() {
        getLoadingViewController().m3284b();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    public void loadingView() {
        getLoadingViewController().m3285c();
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x004c, code lost:
    
        if (getRightIconRes() == (-1)) goto L16;
     */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    @androidx.annotation.CallSuper
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onCreate(@org.jetbrains.annotations.Nullable android.os.Bundle r3) {
        /*
            r2 = this;
            com.qunidayede.supportlibrary.databinding.ViewRootBinding r0 = r2.getRootBinding()
            android.widget.FrameLayout r0 = r0.getRoot()
            super.setContentView(r0)
            super.onCreate(r3)
            r3 = 1
            com.github.anzewei.parallaxbacklayout.widget.ParallaxBackLayout r0 = p005b.p190k.p191a.p192a.C1882c.m1213a(r2, r3)
            r0.setEdgeMode(r3)
            androidx.viewbinding.ViewBinding r0 = r2.getBodyBinding()
            android.view.View r0 = r0.getRoot()
            r2.setContentView(r0)
            r2.initStatusBar()
            java.lang.String r0 = r2.getTopBarTitle()
            int r0 = r0.length()
            r1 = 0
            if (r0 <= 0) goto L31
            r0 = 1
            goto L32
        L31:
            r0 = 0
        L32:
            if (r0 != 0) goto L4e
            java.lang.String r0 = r2.getRightTitle()
            int r0 = r0.length()
            if (r0 <= 0) goto L3f
            r1 = 1
        L3f:
            if (r1 != 0) goto L4e
            boolean r0 = r2.showHomeAsUp()
            if (r0 != 0) goto L4e
            int r0 = r2.getRightIconRes()
            r1 = -1
            if (r0 == r1) goto L51
        L4e:
            r2.inflateTitleBar(r3)
        L51:
            r2.initView()
            r2.bindEvent()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.qunidayede.supportlibrary.core.view.BaseBindingActivity.onCreate(android.os.Bundle):void");
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    public void onError(@NotNull Throwable t) {
        Intrinsics.checkNotNullParameter(t, "t");
        String message = t.getMessage();
        if (message == null) {
            message = "";
        }
        C4325a.m4899b(this, message).show();
    }

    public void onFailedReload(boolean z, int i2, @NotNull Function1<? super View, Unit> function1) {
        C2354n.m2484i1(this, z, i2, function1);
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    @CallSuper
    public void onNewIntent(@Nullable Intent intent) {
        super.onNewIntent(intent);
    }

    public void releaseResources() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    public void removeFailedView() {
        ViewBinding viewBinding = this.failedBinding;
        if (viewBinding == null) {
            return;
        }
        rootBinding(new C4043g(viewBinding));
    }

    public void resetBackClick(@NotNull Function0<Unit> back) {
        FrameLayout frameLayout;
        Intrinsics.checkNotNullParameter(back, "back");
        inflateTitleBar$default(this, false, 1, null);
        TitleBarLayoutBinding titleBarLayoutBinding = this.titleBarBinding;
        if (titleBarLayoutBinding == null || (frameLayout = titleBarLayoutBinding.btnTitleBack) == null) {
            return;
        }
        C2354n.m2380C(frameLayout, 2000L, new C4044h(back));
    }

    public void rootBinding(@NotNull Function1<? super ViewRootBinding, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        block.invoke(getRootBinding());
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    @NotNull
    public LifecycleCoroutineScope scope() {
        return LifecycleOwnerKt.getLifecycleScope(this);
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void setContentView(@Nullable View view) {
        getRootBinding().layoutBody.addView(view, 0, new ViewGroup.LayoutParams(-1, -1));
    }

    public void setRightTitle(@NotNull String title) {
        Intrinsics.checkNotNullParameter(title, "title");
        inflateTitleBar$default(this, false, 1, null);
        TitleBarLayoutBinding titleBarLayoutBinding = this.titleBarBinding;
        TextView textView = titleBarLayoutBinding != null ? titleBarLayoutBinding.tvTitleRight : null;
        if (textView == null) {
            return;
        }
        textView.setText(title);
    }

    public void setTitle(@NotNull String title) {
        Intrinsics.checkNotNullParameter(title, "title");
        inflateTitleBar$default(this, false, 1, null);
        TitleBarLayoutBinding titleBarLayoutBinding = this.titleBarBinding;
        TextView textView = titleBarLayoutBinding != null ? titleBarLayoutBinding.tvTitle : null;
        if (textView == null) {
            return;
        }
        textView.setText(title);
    }

    public final void setTitleBarBinding(@Nullable TitleBarLayoutBinding titleBarLayoutBinding) {
        this.titleBarBinding = titleBarLayoutBinding;
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2846i
    public void showFailedView() {
        ViewBinding failedBinding = getFailedBinding();
        if (failedBinding == null) {
            return;
        }
        rootBinding(new C4046j(failedBinding));
    }

    public boolean showHomeAsUp() {
        Intrinsics.checkNotNullParameter(this, "this");
        return false;
    }

    public void titleBinding(@NotNull Function1<? super TitleBarLayoutBinding, Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        TitleBarLayoutBinding titleBarLayoutBinding = this.titleBarBinding;
        if (titleBarLayoutBinding == null) {
            return;
        }
        block.invoke(titleBarLayoutBinding);
    }
}
