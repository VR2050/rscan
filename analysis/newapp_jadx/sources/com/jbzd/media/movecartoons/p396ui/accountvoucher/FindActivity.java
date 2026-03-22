package com.jbzd.media.movecartoons.p396ui.accountvoucher;

import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.view.View;
import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.core.net.MailTo;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.TokenBean;
import com.jbzd.media.movecartoons.databinding.ActFindBinding;
import com.jbzd.media.movecartoons.p396ui.accountvoucher.FindActivity;
import com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.RetrieveAccountDialog;
import com.king.zxing.CaptureActivity;
import com.luck.picture.lib.PictureSelector;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.listener.OnResultCallbackListener;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseBindingActivity;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.C0885h;
import p005b.p006a.p007a.p008a.p009a.C0875w;
import p005b.p006a.p007a.p008a.p017r.InterfaceC0921e;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p139f.p140a.p142b.C1537g;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p325v.p326a.C2818e;
import p379c.p380a.p383b2.C3016l;
import p426f.p427a.p428a.C4325a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 \u001a2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002\u001a\u001bB\u0007¢\u0006\u0004\b\u0019\u0010\u0011J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u0017\u0010\t\u001a\u00020\u00052\u0006\u0010\b\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\t\u0010\u0007J\u0017\u0010\f\u001a\u00020\u00052\u0006\u0010\u000b\u001a\u00020\nH\u0002¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0010\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\r\u0010\u0012\u001a\u00020\u0005¢\u0006\u0004\b\u0012\u0010\u0011J\r\u0010\u0013\u001a\u00020\u0005¢\u0006\u0004\b\u0013\u0010\u0011R$\u0010\u0017\u001a\u0010\u0012\f\u0012\n \u0016*\u0004\u0018\u00010\u00150\u00150\u00148\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0017\u0010\u0018¨\u0006\u001c"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/accountvoucher/FindActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActFindBinding;", "", "path", "", "parsePhoto", "(Ljava/lang/String;)V", "qrCode", "parseQrCode", "Lcom/jbzd/media/movecartoons/bean/TokenBean;", "token", "findSuccess", "(Lcom/jbzd/media/movecartoons/bean/TokenBean;)V", "getTopBarTitle", "()Ljava/lang/String;", "initView", "()V", "checkPermission", "selectQrCode", "Landroidx/activity/result/ActivityResultLauncher;", "Landroid/content/Intent;", "kotlin.jvm.PlatformType", "launcher", "Landroidx/activity/result/ActivityResultLauncher;", "<init>", "Companion", "ItemClick", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class FindActivity extends BaseBindingActivity<ActFindBinding> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private final ActivityResultLauncher<Intent> launcher;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/accountvoucher/FindActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, FindActivity.class);
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\f\u0010\rJ\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\u0007\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0007\u0010\u0006J\u0015\u0010\n\u001a\u00020\u00042\u0006\u0010\t\u001a\u00020\b¢\u0006\u0004\b\n\u0010\u000b¨\u0006\u000e"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/accountvoucher/FindActivity$ItemClick;", "", "Landroid/content/Context;", "context", "", "sendEmail", "(Landroid/content/Context;)V", "selectRetrieveMethod", "Landroid/view/View;", "view", "onClick", "(Landroid/view/View;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class ItemClick {

        @NotNull
        public static final ItemClick INSTANCE = new ItemClick();

        private ItemClick() {
        }

        private final void selectRetrieveMethod(final Context context) {
            new RetrieveAccountDialog(new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.accountvoucher.FindActivity$ItemClick$selectRetrieveMethod$1
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(View view) {
                    invoke2(view);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull View $receiver) {
                    Intrinsics.checkNotNullParameter($receiver, "$this$$receiver");
                    if ($receiver.getId() == R.id.txt_scan) {
                        ((FindActivity) context).checkPermission();
                    } else {
                        ((FindActivity) context).selectQrCode();
                    }
                }
            }).show(((FindActivity) context).getSupportFragmentManager(), "a");
        }

        private final void sendEmail(Context context) {
            Intent intent = new Intent("android.intent.action.SENDTO");
            intent.setData(Uri.parse(MailTo.MAILTO_SCHEME));
            intent.putExtra("android.intent.extra.EMAIL", new String[]{C0885h.f329a});
            intent.putExtra("android.intent.extra.SUBJECT", context.getString(R.string.setting_account_find));
            C2354n.m2398I(C0885h.f329a);
            if (intent.resolveActivity(context.getPackageManager()) != null) {
                context.startActivity(intent);
            } else {
                C2354n.m2449Z(context.getString(R.string.setting_email_unfound));
            }
        }

        public final void onClick(@NotNull View view) {
            Intrinsics.checkNotNullParameter(view, "view");
            switch (view.getId()) {
                case R.id.layout_find_email /* 2131362620 */:
                    Context context = view.getContext();
                    Intrinsics.checkNotNullExpressionValue(context, "view.context");
                    sendEmail(context);
                    break;
                case R.id.layout_find_service /* 2131362621 */:
                    ChatDetailActivity.Companion companion = ChatDetailActivity.INSTANCE;
                    Context context2 = view.getContext();
                    Intrinsics.checkNotNullExpressionValue(context2, "view.context");
                    ChatDetailActivity.Companion.start$default(companion, context2, null, null, null, null, 30, null);
                    break;
                case R.id.layout_retrieve_account /* 2131362630 */:
                    Context context3 = view.getContext();
                    Intrinsics.checkNotNullExpressionValue(context3, "view.context");
                    selectRetrieveMethod(context3);
                    break;
            }
        }
    }

    public FindActivity() {
        ActivityResultLauncher<Intent> registerForActivityResult = registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), new ActivityResultCallback() { // from class: b.a.a.a.t.a.a
            @Override // androidx.activity.result.ActivityResultCallback
            public final void onActivityResult(Object obj) {
                FindActivity.m5743launcher$lambda0(FindActivity.this, (ActivityResult) obj);
            }
        });
        Intrinsics.checkNotNullExpressionValue(registerForActivityResult, "registerForActivityResult(StartActivityForResult()) { result ->\n        if (result.resultCode == Activity.RESULT_OK) {\n            val qrCode = result.data?.getStringExtra(Intents.Scan.RESULT) ?: \"\"\n            parseQrCode(qrCode)\n        }\n    }");
        this.launcher = registerForActivityResult;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: checkPermission$lambda-1, reason: not valid java name */
    public static final void m5742checkPermission$lambda1(FindActivity this$0, boolean z, List noName_1, List noName_2, List noName_3) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(noName_1, "$noName_1");
        Intrinsics.checkNotNullParameter(noName_2, "$noName_2");
        Intrinsics.checkNotNullParameter(noName_3, "$noName_3");
        if (z) {
            this$0.launcher.launch(new Intent(this$0, (Class<?>) ScanActivity.class));
        } else {
            Typeface typeface = C4325a.f11166a;
            C4325a.m4900c(this$0, this$0.getString(R.string.no_camera_permission), 0, true).show();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void findSuccess(TokenBean token) {
        MyApp myApp = MyApp.f9891f;
        MyApp.m4188i(token);
        C2354n.m2409L1(getString(R.string.account_find_scucess));
        finishAffinity();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: launcher$lambda-0, reason: not valid java name */
    public static final void m5743launcher$lambda0(FindActivity this$0, ActivityResult activityResult) {
        String stringExtra;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (activityResult.getResultCode() == -1) {
            Intent data = activityResult.getData();
            String str = "";
            if (data != null && (stringExtra = data.getStringExtra(CaptureActivity.KEY_RESULT)) != null) {
                str = stringExtra;
            }
            this$0.parseQrCode(str);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void parsePhoto(String path) {
        C2354n.m2441W0(C2354n.m2465d0(new C3016l(new FindActivity$parsePhoto$1(path, null)), new FindActivity$parsePhoto$2(null)), this, new Function1<TokenBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.accountvoucher.FindActivity$parsePhoto$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TokenBean tokenBean) {
                invoke2(tokenBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TokenBean lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                FindActivity.this.findSuccess(lifecycleLoadingDialog);
            }
        }, false, null, 12);
    }

    private final void parseQrCode(String qrCode) {
        Lazy lazy = LazyKt__LazyJVMKt.lazy(C0944a.a.f472c);
        Intrinsics.checkNotNullParameter(qrCode, "code");
        C2354n.m2441W0(((InterfaceC0921e) lazy.getValue()).m252k(qrCode), this, new Function1<TokenBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.accountvoucher.FindActivity$parseQrCode$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TokenBean tokenBean) {
                invoke2(tokenBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TokenBean lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                FindActivity.this.findSuccess(lifecycleLoadingDialog);
            }
        }, false, null, 12);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    public final void checkPermission() {
        C1537g c1537g = new C1537g("android.permission.CAMERA");
        c1537g.f1739f = new C1537g.d() { // from class: b.a.a.a.t.a.b
            @Override // p005b.p139f.p140a.p142b.C1537g.d
            /* renamed from: a */
            public final void mo300a(boolean z, List list, List list2, List list3) {
                FindActivity.m5742checkPermission$lambda1(FindActivity.this, z, list, list2, list3);
            }
        };
        c1537g.m700e();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.mine_retrieve_account);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.mine_retrieve_account)");
        return string;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        getBodyBinding().tvEmail.setText(C0885h.f329a);
    }

    public final void selectQrCode() {
        PictureSelector.create(this).openGallery(PictureMimeType.ofImage()).imageEngine(C0875w.m204a()).selectionMode(1).forResult(new OnResultCallbackListener<LocalMedia>() { // from class: com.jbzd.media.movecartoons.ui.accountvoucher.FindActivity$selectQrCode$1
            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onCancel() {
            }

            @Override // com.luck.picture.lib.listener.OnResultCallbackListener
            public void onResult(@Nullable List<LocalMedia> result) {
                if (result == null || result.isEmpty()) {
                    return;
                }
                int i2 = Build.VERSION.SDK_INT;
                C2818e.m3272a(Intrinsics.stringPlus("Build.VERSION.SDK_INT:", Integer.valueOf(i2)), new Object[0]);
                boolean z = i2 <= 28;
                LocalMedia localMedia = result.get(0);
                String selectPath = z ? localMedia.getPath() : localMedia.getRealPath();
                FindActivity findActivity = FindActivity.this;
                Intrinsics.checkNotNullExpressionValue(selectPath, "selectPath");
                findActivity.parsePhoto(selectPath);
            }
        });
    }
}
