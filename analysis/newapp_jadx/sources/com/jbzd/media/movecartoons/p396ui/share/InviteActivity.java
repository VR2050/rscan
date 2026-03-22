package com.jbzd.media.movecartoons.p396ui.share;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Typeface;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatButton;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.view.ViewCompat;
import androidx.core.view.ViewKt;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.bean.response.ShareInfoBean;
import com.jbzd.media.movecartoons.databinding.ActShareBinding;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseBindingActivity;
import com.qunidayede.supportlibrary.databinding.TitleBarLayoutBinding;
import java.util.HashMap;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0848h;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p006a.p007a.p008a.p017r.InterfaceC0921e;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p139f.p140a.p142b.C1537g;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p426f.p427a.p428a.C4325a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 !2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001!B\u0007¢\u0006\u0004\b \u0010\tJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\n\u0010\tJ\u000f\u0010\u000b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u000b\u0010\tJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u0010\u001a\u00020\u000fH\u0016¢\u0006\u0004\b\u0010\u0010\u0011R\u001d\u0010\u0017\u001a\u00020\u00128F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016R\u001d\u0010\u001a\u001a\u00020\u00128F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0014\u001a\u0004\b\u0019\u0010\u0016R\u001d\u0010\u001f\u001a\u00020\u001b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0014\u001a\u0004\b\u001d\u0010\u001e¨\u0006\""}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/share/InviteActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActShareBinding;", "Lcom/jbzd/media/movecartoons/bean/response/ShareInfoBean;", "shareInfo", "", "showInvite", "(Lcom/jbzd/media/movecartoons/bean/response/ShareInfoBean;)V", "saveQrCode", "()V", "bindEvent", "clickRight", "", "showHomeAsUp", "()Z", "", "getTopBarTitle", "()Ljava/lang/String;", "Landroid/widget/TextView;", "tv_app_name$delegate", "Lkotlin/Lazy;", "getTv_app_name", "()Landroid/widget/TextView;", "tv_app_name", "tv_app_name_tips$delegate", "getTv_app_name_tips", "tv_app_name_tips", "Landroidx/appcompat/widget/AppCompatButton;", "btn_copy_link$delegate", "getBtn_copy_link", "()Landroidx/appcompat/widget/AppCompatButton;", "btn_copy_link", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class InviteActivity extends BaseBindingActivity<ActShareBinding> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: tv_app_name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_app_name = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.share.InviteActivity$tv_app_name$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) InviteActivity.this.findViewById(R.id.tv_app_name);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_app_name_tips$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_app_name_tips = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.share.InviteActivity$tv_app_name_tips$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) InviteActivity.this.findViewById(R.id.tv_app_name_tips);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: btn_copy_link$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_copy_link = LazyKt__LazyJVMKt.lazy(new Function0<AppCompatButton>() { // from class: com.jbzd.media.movecartoons.ui.share.InviteActivity$btn_copy_link$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AppCompatButton invoke() {
            AppCompatButton appCompatButton = (AppCompatButton) InviteActivity.this.findViewById(R.id.btn_copy_link);
            Intrinsics.checkNotNull(appCompatButton);
            return appCompatButton;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/share/InviteActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, InviteActivity.class);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void saveQrCode() {
        C1537g c1537g = new C1537g("android.permission.WRITE_EXTERNAL_STORAGE");
        c1537g.f1739f = new C1537g.d() { // from class: b.a.a.a.t.o.a
            @Override // p005b.p139f.p140a.p142b.C1537g.d
            /* renamed from: a */
            public final void mo300a(boolean z, List list, List list2, List list3) {
                InviteActivity.m6004saveQrCode$lambda1(InviteActivity.this, z, list, list2, list3);
            }
        };
        c1537g.m700e();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: saveQrCode$lambda-1, reason: not valid java name */
    public static final void m6004saveQrCode$lambda1(InviteActivity this$0, boolean z, List noName_1, List noName_2, List noName_3) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(noName_1, "$noName_1");
        Intrinsics.checkNotNullParameter(noName_2, "$noName_2");
        Intrinsics.checkNotNullParameter(noName_3, "$noName_3");
        if (!z) {
            Typeface typeface = C4325a.f11166a;
            C4325a.m4900c(this$0, this$0.getString(R.string.share_no_permission), 0, true).show();
            return;
        }
        ConstraintLayout constraintLayout = this$0.getBodyBinding().layoutInviteHeader;
        Intrinsics.checkNotNullExpressionValue(constraintLayout, "bodyBinding.layoutInviteHeader");
        C2354n.m2523v1(this$0, ViewKt.drawToBitmap$default(constraintLayout, null, 1, null), "Share");
        Typeface typeface2 = C4325a.f11166a;
        C4325a.m4903f(this$0, this$0.getString(R.string.save_sccuess), 0, true).show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showInvite(final ShareInfoBean shareInfo) {
        final Bitmap m2410M = C2354n.m2410M(shareInfo.getShare_link(), C2354n.m2425R(this, 200.0f), C2354n.m2425R(this, 200.0f));
        bodyBinding(new Function1<ActShareBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.share.InviteActivity$showInvite$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActShareBinding actShareBinding) {
                invoke2(actShareBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ActShareBinding bodyBinding) {
                String str;
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                TextView tv_app_name = InviteActivity.this.getTv_app_name();
                InviteActivity context = InviteActivity.this;
                Intrinsics.checkNotNullParameter(context, "context");
                try {
                    PackageManager packageManager = context.getPackageManager();
                    ApplicationInfo applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 128);
                    Intrinsics.checkNotNullExpressionValue(applicationInfo, "manager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)");
                    str = (String) packageManager.getApplicationLabel(applicationInfo);
                } catch (PackageManager.NameNotFoundException unused) {
                    str = "";
                }
                tv_app_name.setText(str);
                InviteActivity.this.getTv_app_name_tips().setText("满足你的所有想象");
                AppCompatButton btn_copy_link = InviteActivity.this.getBtn_copy_link();
                final ShareInfoBean shareInfoBean = shareInfo;
                C2354n.m2374A(btn_copy_link, 0L, new Function1<AppCompatButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.share.InviteActivity$showInvite$1.1
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(AppCompatButton appCompatButton) {
                        invoke2(appCompatButton);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull AppCompatButton it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        String share_link = ShareInfoBean.this.getShare_link();
                        Intrinsics.checkNotNullExpressionValue(share_link, "shareInfo.share_link");
                        C2354n.m2398I(share_link);
                    }
                }, 1);
                AppCompatButton appCompatButton = bodyBinding.btnSaveImage;
                final InviteActivity inviteActivity = InviteActivity.this;
                C2354n.m2374A(appCompatButton, 0L, new Function1<AppCompatButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.share.InviteActivity$showInvite$1.2
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(AppCompatButton appCompatButton2) {
                        invoke2(appCompatButton2);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull AppCompatButton it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        InviteActivity.this.saveQrCode();
                    }
                }, 1);
                bodyBinding.ivCode.setImageBitmap(m2410M);
                bodyBinding.tvCode.setText(shareInfo.getShare_code());
                bodyBinding.txtShareUrl.setText(InviteActivity.this.getString(R.string.invite_official_url, new Object[]{shareInfo.getSite_url()}));
            }
        });
        titleBinding(new Function1<TitleBarLayoutBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.share.InviteActivity$showInvite$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TitleBarLayoutBinding titleBarLayoutBinding) {
                invoke2(titleBarLayoutBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TitleBarLayoutBinding titleBinding) {
                Intrinsics.checkNotNullParameter(titleBinding, "$this$titleBinding");
                titleBinding.ivTitleLeftIcon.setImageResource(R.drawable.ic_btn_icon_black);
                ((ImageView) InviteActivity.this.getTitleLayout().findViewById(R.id.iv_titleLeftIcon)).setColorFilter(ViewCompat.MEASURED_STATE_MASK);
                titleBinding.tvTitleRight.setText(InviteActivity.this.getString(R.string.mine_share));
                titleBinding.tvTitleRight.setTextSize(13.0f);
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("object_type", "share");
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "system/track", Object.class, m595Q, C0848h.f250c, null, false, false, null, false, 432);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
        C2354n.m2441W0(((InterfaceC0921e) LazyKt__LazyJVMKt.lazy(C0944a.a.f472c).getValue()).m256o(), this, new Function1<ShareInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.share.InviteActivity$bindEvent$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ShareInfoBean shareInfoBean) {
                invoke2(shareInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ShareInfoBean lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                InviteActivity.this.showInvite(lifecycleLoadingDialog);
            }
        }, false, null, 12);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void clickRight() {
        ShareListActivity.INSTANCE.start(this);
    }

    @NotNull
    public final AppCompatButton getBtn_copy_link() {
        return (AppCompatButton) this.btn_copy_link.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        return "分享邀请";
    }

    @NotNull
    public final TextView getTv_app_name() {
        return (TextView) this.tv_app_name.getValue();
    }

    @NotNull
    public final TextView getTv_app_name_tips() {
        return (TextView) this.tv_app_name_tips.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public boolean showHomeAsUp() {
        return true;
    }
}
