package com.jbzd.media.movecartoons.view;

import android.app.Activity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.widget.ActivityChooserModel;
import androidx.fragment.app.Fragment;
import com.jbzd.media.movecartoons.p396ui.dialog.StrongBottomSheetDialog;
import com.jbzd.media.movecartoons.p396ui.post.PostInputActivity;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostAiCanvasActivity;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostAiChangeFaceActivity;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostAiClearClosethActivity;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p337d.C2861e;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\b\n\u0002\b\u0007\u0018\u0000 >2\u00020\u00012\u00020\u0002:\u0002>?B'\u0012\u0006\u00102\u001a\u000201\u0012\u0006\u0010\u000b\u001a\u00020\n\u0012\u0006\u0010:\u001a\u000209\u0012\u0006\u0010;\u001a\u000209¢\u0006\u0004\b<\u0010=J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u0017\u0010\b\u001a\u00020\u00032\b\u0010\u0007\u001a\u0004\u0018\u00010\u0006¢\u0006\u0004\b\b\u0010\tJ\u0017\u0010\f\u001a\u00020\u00032\b\u0010\u000b\u001a\u0004\u0018\u00010\n¢\u0006\u0004\b\f\u0010\rJ\r\u0010\u000e\u001a\u00020\u0003¢\u0006\u0004\b\u000e\u0010\u0005J\u000f\u0010\u000f\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u000f\u0010\u0005J\u0017\u0010\u0012\u001a\u00020\u00032\u0006\u0010\u0011\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u0012\u0010\u0013R\u0018\u0010\u0014\u001a\u0004\u0018\u00010\n8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0014\u0010\u0015R\u001d\u0010\u001b\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0017\u0010\u0018\u001a\u0004\b\u0019\u0010\u001aR%\u0010 \u001a\n \u001c*\u0004\u0018\u00010\u00100\u00108B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u0018\u001a\u0004\b\u001e\u0010\u001fR\u001d\u0010#\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u0018\u001a\u0004\b\"\u0010\u001aR\u001d\u0010(\u001a\u00020$8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u0018\u001a\u0004\b&\u0010'R\u001d\u0010+\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b)\u0010\u0018\u001a\u0004\b*\u0010\u001aR\u001d\u00100\u001a\u00020,8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u0018\u001a\u0004\b.\u0010/R\u0016\u00102\u001a\u0002018\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b2\u00103R\u0018\u00104\u001a\u0004\u0018\u00010\u00068\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b4\u00105R\u001d\u00108\u001a\u00020\u00168F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b6\u0010\u0018\u001a\u0004\b7\u0010\u001a¨\u0006@"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog;", "Lcom/jbzd/media/movecartoons/ui/dialog/StrongBottomSheetDialog;", "Landroid/view/View$OnClickListener;", "", "initDefaultShow", "()V", "Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog$EventListener;", "eventListener", "setEventListener", "(Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog$EventListener;)V", "Landroidx/fragment/app/Fragment;", "mFragment", "setFragment", "(Landroidx/fragment/app/Fragment;)V", "init", "dismiss", "Landroid/view/View;", "v", "onClick", "(Landroid/view/View;)V", "fragment", "Landroidx/fragment/app/Fragment;", "Landroid/widget/LinearLayout;", "ll_dialog_postaitype_clearcloseth$delegate", "Lkotlin/Lazy;", "getLl_dialog_postaitype_clearcloseth", "()Landroid/widget/LinearLayout;", "ll_dialog_postaitype_clearcloseth", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "ll_dialog_postaitype_post$delegate", "getLl_dialog_postaitype_post", "ll_dialog_postaitype_post", "Landroid/widget/TextView;", "btn_cancel$delegate", "getBtn_cancel", "()Landroid/widget/TextView;", "btn_cancel", "ll_dialog_postaitype_changeface$delegate", "getLl_dialog_postaitype_changeface", "ll_dialog_postaitype_changeface", "Landroid/widget/ImageView;", "iv_posttype_cancel$delegate", "getIv_posttype_cancel", "()Landroid/widget/ImageView;", "iv_posttype_cancel", "Landroid/app/Activity;", "context", "Landroid/app/Activity;", "listener", "Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog$EventListener;", "ll_dialog_postaitype_canvas$delegate", "getLl_dialog_postaitype_canvas", "ll_dialog_postaitype_canvas", "", "peekHeight", "maxHeight", "<init>", "(Landroid/app/Activity;Landroidx/fragment/app/Fragment;II)V", "Companion", "EventListener", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostAiTypeDialog extends StrongBottomSheetDialog implements View.OnClickListener {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: btn_cancel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_cancel;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final Activity context;

    @Nullable
    private Fragment fragment;

    /* renamed from: iv_posttype_cancel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_posttype_cancel;

    @Nullable
    private EventListener listener;

    /* renamed from: ll_dialog_postaitype_canvas$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_dialog_postaitype_canvas;

    /* renamed from: ll_dialog_postaitype_changeface$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_dialog_postaitype_changeface;

    /* renamed from: ll_dialog_postaitype_clearcloseth$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_dialog_postaitype_clearcloseth;

    /* renamed from: ll_dialog_postaitype_post$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_dialog_postaitype_post;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog$Companion;", "", "Landroid/app/Activity;", ActivityChooserModel.ATTRIBUTE_ACTIVITY, "Landroidx/fragment/app/Fragment;", "fragment", "Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog;", "showPostTypeDialog", "(Landroid/app/Activity;Landroidx/fragment/app/Fragment;)Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final PostAiTypeDialog showPostTypeDialog(@NotNull Activity activity, @NotNull Fragment fragment) {
            View findViewById;
            Intrinsics.checkNotNullParameter(activity, "activity");
            Intrinsics.checkNotNullParameter(fragment, "fragment");
            int m2513s0 = (C2354n.m2513s0(activity) * 2) / 3;
            PostAiTypeDialog postAiTypeDialog = new PostAiTypeDialog(activity, fragment, m2513s0, m2513s0);
            postAiTypeDialog.init();
            Window window = postAiTypeDialog.getWindow();
            if (window != null && (findViewById = window.findViewById(R.id.design_bottom_sheet)) != null) {
                findViewById.setBackgroundResource(android.R.color.transparent);
            }
            return postAiTypeDialog;
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H&¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0005"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/PostAiTypeDialog$EventListener;", "", "", "onPay", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public interface EventListener {
        void onPay();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public PostAiTypeDialog(@NotNull Activity context, @NotNull Fragment mFragment, int i2, int i3) {
        super(context, i2, i3, R.style.TransBottomSheetDialogStyle);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(mFragment, "mFragment");
        this.context = context;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.view.PostAiTypeDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                Activity activity;
                activity = PostAiTypeDialog.this.context;
                return LayoutInflater.from(activity).inflate(R.layout.dialog_aipost_type, (ViewGroup) null);
            }
        });
        this.ll_dialog_postaitype_post = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.view.PostAiTypeDialog$ll_dialog_postaitype_post$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View contentView;
                contentView = PostAiTypeDialog.this.getContentView();
                LinearLayout linearLayout = (LinearLayout) contentView.findViewById(R.id.ll_dialog_postaitype_post);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.ll_dialog_postaitype_clearcloseth = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.view.PostAiTypeDialog$ll_dialog_postaitype_clearcloseth$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View contentView;
                contentView = PostAiTypeDialog.this.getContentView();
                LinearLayout linearLayout = (LinearLayout) contentView.findViewById(R.id.ll_dialog_postaitype_clearcloseth);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.ll_dialog_postaitype_changeface = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.view.PostAiTypeDialog$ll_dialog_postaitype_changeface$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View contentView;
                contentView = PostAiTypeDialog.this.getContentView();
                LinearLayout linearLayout = (LinearLayout) contentView.findViewById(R.id.ll_dialog_postaitype_changeface);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.ll_dialog_postaitype_canvas = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.view.PostAiTypeDialog$ll_dialog_postaitype_canvas$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View contentView;
                contentView = PostAiTypeDialog.this.getContentView();
                LinearLayout linearLayout = (LinearLayout) contentView.findViewById(R.id.ll_dialog_postaitype_canvas);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.iv_posttype_cancel = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.view.PostAiTypeDialog$iv_posttype_cancel$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageView invoke() {
                View contentView;
                contentView = PostAiTypeDialog.this.getContentView();
                ImageView imageView = (ImageView) contentView.findViewById(R.id.iv_posttype_cancel);
                Intrinsics.checkNotNull(imageView);
                return imageView;
            }
        });
        this.btn_cancel = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.view.PostAiTypeDialog$btn_cancel$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = PostAiTypeDialog.this.getContentView();
                TextView textView = (TextView) contentView.findViewById(R.id.btn_cancel);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final void initDefaultShow() {
        getLl_dialog_postaitype_post().setOnClickListener(this);
        getLl_dialog_postaitype_clearcloseth().setOnClickListener(this);
        getLl_dialog_postaitype_changeface().setOnClickListener(this);
        getLl_dialog_postaitype_canvas().setOnClickListener(this);
        getIv_posttype_cancel().setOnClickListener(this);
        getBtn_cancel().setOnClickListener(this);
    }

    @Override // androidx.appcompat.app.AppCompatDialog, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        View currentFocus = getCurrentFocus();
        if (currentFocus instanceof EditText) {
            C2861e.m3306d(currentFocus);
        }
        super.dismiss();
    }

    @NotNull
    public final TextView getBtn_cancel() {
        return (TextView) this.btn_cancel.getValue();
    }

    @NotNull
    public final ImageView getIv_posttype_cancel() {
        return (ImageView) this.iv_posttype_cancel.getValue();
    }

    @NotNull
    public final LinearLayout getLl_dialog_postaitype_canvas() {
        return (LinearLayout) this.ll_dialog_postaitype_canvas.getValue();
    }

    @NotNull
    public final LinearLayout getLl_dialog_postaitype_changeface() {
        return (LinearLayout) this.ll_dialog_postaitype_changeface.getValue();
    }

    @NotNull
    public final LinearLayout getLl_dialog_postaitype_clearcloseth() {
        return (LinearLayout) this.ll_dialog_postaitype_clearcloseth.getValue();
    }

    @NotNull
    public final LinearLayout getLl_dialog_postaitype_post() {
        return (LinearLayout) this.ll_dialog_postaitype_post.getValue();
    }

    public final void init() {
        setContentView(getContentView());
        initDefaultShow();
    }

    @Override // android.view.View.OnClickListener
    public void onClick(@NotNull View v) {
        Intrinsics.checkNotNullParameter(v, "v");
        int id = v.getId();
        if (id == R.id.btn_cancel) {
            onBackPressed();
        }
        if (id == R.id.iv_posttype_cancel) {
            onBackPressed();
            return;
        }
        switch (id) {
            case R.id.ll_dialog_postaitype_canvas /* 2131362705 */:
                PostAiCanvasActivity.INSTANCE.start(this.context);
                dismiss();
                break;
            case R.id.ll_dialog_postaitype_changeface /* 2131362706 */:
                PostAiChangeFaceActivity.INSTANCE.startAIChangeFace(this.context);
                dismiss();
                break;
            case R.id.ll_dialog_postaitype_clearcloseth /* 2131362707 */:
                PostAiClearClosethActivity.INSTANCE.start(this.context);
                dismiss();
                break;
            case R.id.ll_dialog_postaitype_post /* 2131362708 */:
                PostInputActivity.INSTANCE.start(this.context, 3, "homepage", "post");
                dismiss();
                break;
        }
    }

    public final void setEventListener(@Nullable EventListener eventListener) {
        this.listener = eventListener;
    }

    public final void setFragment(@Nullable Fragment mFragment) {
        this.fragment = mFragment;
    }
}
