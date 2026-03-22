package com.jbzd.media.movecartoons.p396ui.download;

import android.view.View;
import android.widget.TextView;
import com.jbzd.media.movecartoons.p396ui.dialog.XAlertDialog;
import com.jbzd.media.movecartoons.p396ui.download.DownloadActivity;
import com.jbzd.media.movecartoons.p396ui.download.DownloadActivity$bindEvent$3;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0003\u0010\u0004"}, m5311d2 = {"Landroid/widget/TextView;", "it", "", "<anonymous>", "(Landroid/widget/TextView;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class DownloadActivity$bindEvent$3 extends Lambda implements Function1<TextView, Unit> {
    public final /* synthetic */ DownloadActivity this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public DownloadActivity$bindEvent$3(DownloadActivity downloadActivity) {
        super(1);
        this.this$0 = downloadActivity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-0, reason: not valid java name */
    public static final void m5799invoke$lambda0(DownloadActivity this$0, View view) {
        ListFragment listFragment;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        listFragment = this$0.getListFragment();
        listFragment.clearAll();
    }

    @Override // kotlin.jvm.functions.Function1
    public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
        invoke2(textView);
        return Unit.INSTANCE;
    }

    /* renamed from: invoke, reason: avoid collision after fix types in other method */
    public final void invoke2(@NotNull TextView it) {
        XAlertDialog dialog;
        Intrinsics.checkNotNullParameter(it, "it");
        this.this$0.getBtnDel().setVisibility(8);
        dialog = this.this$0.getDialog();
        XAlertDialog msg = dialog.setMsg("是否清除缓存视频？");
        final DownloadActivity downloadActivity = this.this$0;
        msg.setPositiveButton("确定", new View.OnClickListener() { // from class: b.a.a.a.t.f.a
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                DownloadActivity$bindEvent$3.m5799invoke$lambda0(DownloadActivity.this, view);
            }
        }).setNegativeButton("取消", null).show();
    }
}
