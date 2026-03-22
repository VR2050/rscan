package com.jbzd.media.movecartoons.p396ui.dialog;

import androidx.core.app.NotificationCompat;
import androidx.fragment.app.FragmentManager;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\f\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0017\u0010\u0018JK\u0010\u000e\u001a\u00020\r2\u0006\u0010\u0003\u001a\u00020\u00022\b\b\u0002\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u00042\b\b\u0002\u0010\u0007\u001a\u00020\u00042\b\b\u0002\u0010\t\u001a\u00020\b2\u000e\b\u0002\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\n¢\u0006\u0004\b\u000e\u0010\u000fJM\u0010\u0015\u001a\u00020\r2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0010\u001a\u00020\u00042\u0006\u0010\u0011\u001a\u00020\u00042\b\b\u0002\u0010\u0012\u001a\u00020\b2\f\u0010\u0013\u001a\b\u0012\u0004\u0012\u00020\u000b0\n2\u000e\b\u0002\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u000b0\n¢\u0006\u0004\b\u0015\u0010\u0016¨\u0006\u0019"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/DialogController;", "", "Landroidx/fragment/app/FragmentManager;", "fragmentManager", "", VideoListActivity.KEY_TITLE, NotificationCompat.CATEGORY_MESSAGE, "positiveText", "", "cancelable", "Lkotlin/Function0;", "", "positiveBlock", "Lcom/jbzd/media/movecartoons/ui/dialog/BaseDialog;", "showHintDialog", "(Landroidx/fragment/app/FragmentManager;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLkotlin/jvm/functions/Function0;)Lcom/jbzd/media/movecartoons/ui/dialog/BaseDialog;", "updateMsg", "newVersion", "isMandatoryUpdate", "confirmBlock", "cancelBlock", "showUpdateDialog", "(Landroidx/fragment/app/FragmentManager;Ljava/lang/String;Ljava/lang/String;ZLkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;)Lcom/jbzd/media/movecartoons/ui/dialog/BaseDialog;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class DialogController {

    @NotNull
    public static final DialogController INSTANCE = new DialogController();

    private DialogController() {
    }

    public static /* synthetic */ BaseDialog showHintDialog$default(DialogController dialogController, FragmentManager fragmentManager, String str, String str2, String str3, boolean z, Function0 function0, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            str = "提示";
        }
        String str4 = str;
        if ((i2 & 8) != 0) {
            str3 = "确定";
        }
        String str5 = str3;
        boolean z2 = (i2 & 16) != 0 ? true : z;
        if ((i2 & 32) != 0) {
            function0 = new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DialogController$showHintDialog$1
                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2() {
                }
            };
        }
        return dialogController.showHintDialog(fragmentManager, str4, str2, str5, z2, function0);
    }

    public static /* synthetic */ BaseDialog showUpdateDialog$default(DialogController dialogController, FragmentManager fragmentManager, String str, String str2, boolean z, Function0 function0, Function0 function02, int i2, Object obj) {
        boolean z2 = (i2 & 8) != 0 ? false : z;
        if ((i2 & 32) != 0) {
            function02 = new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DialogController$showUpdateDialog$1
                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2() {
                }
            };
        }
        return dialogController.showUpdateDialog(fragmentManager, str, str2, z2, function0, function02);
    }

    @NotNull
    public final BaseDialog showHintDialog(@NotNull FragmentManager fragmentManager, @NotNull String title, @NotNull String msg, @NotNull String positiveText, boolean cancelable, @NotNull Function0<Unit> positiveBlock) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(msg, "msg");
        Intrinsics.checkNotNullParameter(positiveText, "positiveText");
        Intrinsics.checkNotNullParameter(positiveBlock, "positiveBlock");
        BaseDialog baseDialog = new BaseDialog(title, msg, null, null, positiveText, positiveBlock, null, null, null, null, null, null, cancelable, null, null, 28620, null);
        baseDialog.show(fragmentManager, "HintDialog");
        return baseDialog;
    }

    @NotNull
    public final BaseDialog showUpdateDialog(@NotNull FragmentManager fragmentManager, @NotNull String updateMsg, @NotNull String newVersion, boolean isMandatoryUpdate, @NotNull Function0<Unit> confirmBlock, @NotNull Function0<Unit> cancelBlock) {
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        Intrinsics.checkNotNullParameter(updateMsg, "updateMsg");
        Intrinsics.checkNotNullParameter(newVersion, "newVersion");
        Intrinsics.checkNotNullParameter(confirmBlock, "confirmBlock");
        Intrinsics.checkNotNullParameter(cancelBlock, "cancelBlock");
        BaseDialog baseDialog = new BaseDialog(Intrinsics.stringPlus(newVersion, "版本升级公告"), updateMsg, null, null, "立即升级", confirmBlock, null, null, isMandatoryUpdate ? null : "暂不升级", cancelBlock, newVersion, null, false, "去保存账号凭证", new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DialogController$showUpdateDialog$baseDialog$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                C2354n.m2379B1("去保存账号凭证");
            }
        }, 2252, null);
        baseDialog.show(fragmentManager, "UpdateDialog");
        return baseDialog;
    }
}
