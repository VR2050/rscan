package com.jbzd.media.movecartoons.view;

import android.app.Activity;
import android.content.Context;
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
import com.jbzd.media.movecartoons.R$id;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0007\u0018\u0000 ,2\u00020\u00012\u00020\u0002:\u0002,-B\u001f\u0012\u0006\u0010#\u001a\u00020\"\u0012\u0006\u0010(\u001a\u00020'\u0012\u0006\u0010)\u001a\u00020'¢\u0006\u0004\b*\u0010+J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u0015\u0010\b\u001a\u00020\u00032\u0006\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\b\u0010\tJ\u0017\u0010\f\u001a\u00020\u00032\b\u0010\u000b\u001a\u0004\u0018\u00010\n¢\u0006\u0004\b\f\u0010\rJ\u0017\u0010\u0010\u001a\u00020\u00032\b\u0010\u000f\u001a\u0004\u0018\u00010\u000e¢\u0006\u0004\b\u0010\u0010\u0011J\r\u0010\u0012\u001a\u00020\u0003¢\u0006\u0004\b\u0012\u0010\u0005J\u000f\u0010\u0013\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0013\u0010\u0005J\u0017\u0010\u0016\u001a\u00020\u00032\u0006\u0010\u0015\u001a\u00020\u0014H\u0016¢\u0006\u0004\b\u0016\u0010\u0017R\u0018\u0010\u0018\u001a\u0004\u0018\u00010\n8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0018\u0010\u0019R%\u0010\u001f\u001a\n \u001a*\u0004\u0018\u00010\u00140\u00148B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u001c\u001a\u0004\b\u001d\u0010\u001eR\u0016\u0010 \u001a\u00020\u00068\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b \u0010!R\u0016\u0010#\u001a\u00020\"8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b#\u0010$R\u0018\u0010%\u001a\u0004\u0018\u00010\u000e8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b%\u0010&¨\u0006."}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/PostTypeDialog;", "Lcom/jbzd/media/movecartoons/ui/dialog/StrongBottomSheetDialog;", "Landroid/view/View$OnClickListener;", "", "initDefaultShow", "()V", "", "typePost", "setPostType", "(Ljava/lang/String;)V", "Lcom/jbzd/media/movecartoons/view/PostTypeDialog$EventListener;", "eventListener", "setEventListener", "(Lcom/jbzd/media/movecartoons/view/PostTypeDialog$EventListener;)V", "Landroidx/fragment/app/Fragment;", "mFragment", "setFragment", "(Landroidx/fragment/app/Fragment;)V", "init", "dismiss", "Landroid/view/View;", "v", "onClick", "(Landroid/view/View;)V", "listener", "Lcom/jbzd/media/movecartoons/view/PostTypeDialog$EventListener;", "kotlin.jvm.PlatformType", "contentView$delegate", "Lkotlin/Lazy;", "getContentView", "()Landroid/view/View;", "contentView", "type_post", "Ljava/lang/String;", "Landroid/app/Activity;", "context", "Landroid/app/Activity;", "fragment", "Landroidx/fragment/app/Fragment;", "", "peekHeight", "maxHeight", "<init>", "(Landroid/app/Activity;II)V", "Companion", "EventListener", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostTypeDialog extends StrongBottomSheetDialog implements View.OnClickListener {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final Activity context;

    @Nullable
    private Fragment fragment;

    @Nullable
    private EventListener listener;

    @NotNull
    private String type_post;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/PostTypeDialog$Companion;", "", "Landroid/app/Activity;", ActivityChooserModel.ATTRIBUTE_ACTIVITY, "Landroidx/fragment/app/Fragment;", "fragment", "Lcom/jbzd/media/movecartoons/view/PostTypeDialog;", "showPostTypeDialog", "(Landroid/app/Activity;Landroidx/fragment/app/Fragment;)Lcom/jbzd/media/movecartoons/view/PostTypeDialog;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final PostTypeDialog showPostTypeDialog(@NotNull Activity activity, @NotNull Fragment fragment) {
            View findViewById;
            Intrinsics.checkNotNullParameter(activity, "activity");
            Intrinsics.checkNotNullParameter(fragment, "fragment");
            int m2513s0 = (C2354n.m2513s0(activity) * 2) / 3;
            PostTypeDialog postTypeDialog = new PostTypeDialog(activity, m2513s0, m2513s0);
            postTypeDialog.init();
            Window window = postTypeDialog.getWindow();
            if (window != null && (findViewById = window.findViewById(R.id.design_bottom_sheet)) != null) {
                findViewById.setBackgroundResource(android.R.color.transparent);
            }
            return postTypeDialog;
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H&¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0005"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/PostTypeDialog$EventListener;", "", "", "onPay", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public interface EventListener {
        void onPay();
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public PostTypeDialog(@NotNull Activity context, int i2, int i3) {
        super(context, i2, i3, R.style.TransBottomSheetDialogStyle);
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.view.PostTypeDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                Activity activity;
                activity = PostTypeDialog.this.context;
                return LayoutInflater.from(activity).inflate(R.layout.dialog_post_type, (ViewGroup) null);
            }
        });
        this.type_post = "";
    }

    private final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final void initDefaultShow() {
        ((LinearLayout) findViewById(R$id.ll_dialog_postaitype_post)).setOnClickListener(this);
        ((LinearLayout) findViewById(R$id.ll_dialog_postaitype_clearcloseth)).setOnClickListener(this);
        ((LinearLayout) findViewById(R$id.ll_dialog_postaitype_changeface)).setOnClickListener(this);
        ((LinearLayout) findViewById(R$id.ll_dialog_postaitype_canvas)).setOnClickListener(this);
        ((ImageView) findViewById(R$id.iv_posttype_cancel)).setOnClickListener(this);
        ((TextView) findViewById(R$id.btn_cancel)).setOnClickListener(this);
    }

    @Override // androidx.appcompat.app.AppCompatDialog, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        View currentFocus = getCurrentFocus();
        if (currentFocus instanceof EditText) {
            C2861e.m3306d(currentFocus);
        }
        super.dismiss();
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
                PostInputActivity.Companion companion = PostInputActivity.INSTANCE;
                Context context = getContext();
                Intrinsics.checkNotNullExpressionValue(context, "getContext()");
                companion.start(context, 3, "homepage", this.type_post);
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

    public final void setPostType(@NotNull String typePost) {
        Intrinsics.checkNotNullParameter(typePost, "typePost");
        this.type_post = typePost;
    }
}
