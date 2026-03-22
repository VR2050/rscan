package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.core.view.ViewKt;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.FragmentActivity;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.qnmd.adnnm.da0yzo.R;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p293n.p294a.C2650h;
import p005b.p293n.p294a.C2657k0;
import p005b.p293n.p294a.C2662p;
import p005b.p293n.p294a.C2665s;
import p005b.p293n.p294a.InterfaceC2652i;
import p426f.p427a.p428a.C4325a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000f\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b \u0010!J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J2\u0010\f\u001a\u00020\n2!\u0010\u000b\u001a\u001d\u0012\u0013\u0012\u00110\u0006¢\u0006\f\b\u0007\u0012\b\b\b\u0012\u0004\b\b(\t\u0012\u0004\u0012\u00020\n0\u0005H\u0002¢\u0006\u0004\b\f\u0010\rJ\u0019\u0010\u0011\u001a\u00020\u00102\b\u0010\u000f\u001a\u0004\u0018\u00010\u000eH\u0016¢\u0006\u0004\b\u0011\u0010\u0012J!\u0010\u0015\u001a\u00020\n2\u0006\u0010\u0014\u001a\u00020\u00132\b\u0010\u000f\u001a\u0004\u0018\u00010\u000eH\u0016¢\u0006\u0004\b\u0015\u0010\u0016R%\u0010\u001c\u001a\n \u0017*\u0004\u0018\u00010\u00130\u00138B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\u001bR\u001d\u0010\u001f\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u0019\u001a\u0004\b\u001e\u0010\u0004¨\u0006\""}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/IdcardDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "pass", "", "resultBlock", "permissionCheck", "(Lkotlin/jvm/functions/Function1;)V", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "kotlin.jvm.PlatformType", "contentView$delegate", "Lkotlin/Lazy;", "getContentView", "()Landroid/view/View;", "contentView", "alertDialog$delegate", "getAlertDialog", "alertDialog", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class IdcardDialog extends DialogFragment {

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.IdcardDialog$contentView$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        public final View invoke() {
            return LayoutInflater.from(IdcardDialog.this.getContext()).inflate(R.layout.dialog_idcard, (ViewGroup) null);
        }
    });

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.IdcardDialog$alertDialog$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AlertDialog invoke() {
            AlertDialog createDialog;
            createDialog = IdcardDialog.this.createDialog();
            return createDialog;
        }
    });

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        String str;
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.dialog_center), getContentView(), "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView)\n            .create()");
        TextView textView = (TextView) getContentView().findViewById(R.id.tv_site_url);
        MyApp myApp = MyApp.f9891f;
        String str2 = MyApp.m4185f().site_url;
        String str3 = "";
        if (str2 == null) {
            str2 = "";
        }
        textView.setText(str2);
        C2354n.m2374A(getContentView().findViewById(R.id.tv_site_url), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.IdcardDialog$createDialog$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView2) {
                String str4;
                String str5;
                Object systemService = IdcardDialog.this.requireContext().getApplicationContext().getSystemService("clipboard");
                Objects.requireNonNull(systemService, "null cannot be cast to non-null type android.content.ClipboardManager");
                ClipboardManager clipboardManager = (ClipboardManager) systemService;
                MyApp myApp2 = MyApp.f9891f;
                UserInfoBean userInfoBean = MyApp.f9892g;
                String str6 = "";
                if (userInfoBean == null || (str4 = userInfoBean.site_url) == null) {
                    str4 = "";
                }
                if (userInfoBean != null && (str5 = userInfoBean.site_url) != null) {
                    str6 = str5;
                }
                clipboardManager.setPrimaryClip(ClipData.newPlainText(str4, str6));
                C2354n.m2409L1("复制网址成功");
            }
        }, 1);
        UserInfoBean userInfoBean = MyApp.f9892g;
        if (userInfoBean != null && (str = userInfoBean.account_slat) != null) {
            str3 = str;
        }
        Bitmap m2410M = C2354n.m2410M(str3, C2354n.m2425R(getContext(), 200.0f), C2354n.m2425R(getContext(), 200.0f));
        TextView textView2 = (TextView) getContentView().findViewById(R.id.btn_save_cardid);
        if (m2410M != null) {
            ((ImageView) getContentView().findViewById(R.id.iv_qrcode_cardid)).setImageBitmap(m2410M);
            C2354n.m2374A(textView2, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.IdcardDialog$createDialog$2
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(TextView textView3) {
                    invoke2(textView3);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(TextView textView3) {
                    final IdcardDialog idcardDialog = IdcardDialog.this;
                    idcardDialog.permissionCheck(new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.IdcardDialog$createDialog$2.1
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                            invoke(bool.booleanValue());
                            return Unit.INSTANCE;
                        }

                        public final void invoke(boolean z) {
                            View contentView;
                            Context context = IdcardDialog.this.getContext();
                            if (z) {
                                contentView = IdcardDialog.this.getContentView();
                                View findViewById = contentView.findViewById(R.id.ll_card_info);
                                Intrinsics.checkNotNullExpressionValue(findViewById, "contentView.findViewById<ImageView>(R.id.ll_card_info)");
                                C2354n.m2523v1(context, ViewKt.drawToBitmap$default(findViewById, null, 1, null), "AccountVoucher");
                                if (context != null) {
                                    C4325a.m4902e(context, "保存成功").show();
                                }
                            } else if (context != null) {
                                C4325a.m4899b(context, "没有权限").show();
                            }
                            IdcardDialog.this.dismissAllowingStateLoss();
                        }
                    });
                }
            }, 1);
        } else {
            C2354n.m2374A(textView2, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.IdcardDialog$createDialog$3
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(TextView textView3) {
                    invoke2(textView3);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(TextView textView3) {
                    C2354n.m2449Z("二维码不存在");
                }
            }, 1);
        }
        Window window = m624j0.getWindow();
        if (window != null) {
            window.setDimAmount(0.8f);
        }
        WindowManager.LayoutParams attributes = window == null ? null : window.getAttributes();
        if (attributes != null) {
            attributes.windowAnimations = R.style.BottomShowAnimation;
        }
        return m624j0;
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void permissionCheck(final Function1<? super Boolean, Unit> resultBlock) {
        C2657k0 c2657k0 = new C2657k0(getActivity());
        c2657k0.m3155a("android.permission.READ_EXTERNAL_STORAGE");
        c2657k0.m3155a("android.permission.WRITE_EXTERNAL_STORAGE");
        c2657k0.m3156b(new InterfaceC2652i() { // from class: com.jbzd.media.movecartoons.ui.dialog.IdcardDialog$permissionCheck$1
            @Override // p005b.p293n.p294a.InterfaceC2652i
            public void onDenied(@NotNull List<String> permissions, boolean doNotAskAgain) {
                Intrinsics.checkNotNullParameter(permissions, "permissions");
                if (!doNotAskAgain) {
                    C4325a.m4899b(IdcardDialog.this.requireContext(), "没有权限").show();
                    return;
                }
                C4325a.m4899b(IdcardDialog.this.requireContext(), "被永久拒绝授权").show();
                FragmentActivity requireActivity = IdcardDialog.this.requireActivity();
                C2650h.m3151n(new C2662p(requireActivity, null), C2665s.m3160b(requireActivity, permissions), 1025);
            }

            @Override // p005b.p293n.p294a.InterfaceC2652i
            public void onGranted(@NotNull List<String> permissions, boolean allGranted) {
                Intrinsics.checkNotNullParameter(permissions, "permissions");
                if (allGranted) {
                    resultBlock.invoke(Boolean.TRUE);
                } else {
                    C4325a.m4899b(IdcardDialog.this.requireContext(), "获取部分权限成功，但部分权限未正常授予").show();
                }
            }
        });
    }

    public void _$_clearFindViewByIdCache() {
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(@NotNull View view, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, savedInstanceState);
    }
}
