package com.jbzd.media.movecartoons.p396ui.share;

import android.content.Context;
import androidx.lifecycle.Observer;
import com.jbzd.media.movecartoons.databinding.ActShareBindBinding;
import com.jbzd.media.movecartoons.p396ui.share.ShareBindActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseVMActivity;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0005\u0018\u0000 \u000b2\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001:\u0001\u000bB\u0007¢\u0006\u0004\b\n\u0010\u0006J\u000f\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\t¨\u0006\f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/share/ShareBindActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseVMActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActShareBindBinding;", "Lcom/jbzd/media/movecartoons/ui/share/BindCodeViewModel;", "", "bindEvent", "()V", "", "getTopBarTitle", "()Ljava/lang/String;", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ShareBindActivity extends BaseVMActivity<ActShareBindBinding, BindCodeViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/share/ShareBindActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, ShareBindActivity.class);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-1$lambda-0, reason: not valid java name */
    public static final void m6005bindEvent$lambda1$lambda0(ShareBindActivity this$0, Boolean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        if (it.booleanValue()) {
            C2354n.m2409L1(this$0.getString(R.string.phone_bind_scucess));
            this$0.finish();
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseVMActivity, com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        getViewModel().getUserInfoUpdateSuccess().observe(this, new Observer() { // from class: b.a.a.a.t.o.b
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                ShareBindActivity.m6005bindEvent$lambda1$lambda0(ShareBindActivity.this, (Boolean) obj);
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.mine_binding_code);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.mine_binding_code)");
        return string;
    }
}
