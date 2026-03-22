package com.jbzd.media.movecartoons.p396ui.chat;

import android.content.Context;
import android.content.Intent;
import com.jbzd.media.movecartoons.bean.response.MsgListBean;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseActivity;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0005\u0018\u0000 \f2\u00020\u0001:\u0001\fB\u0007¢\u0006\u0004\b\u000b\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\t\u0010\n¨\u0006\r"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/chat/NewsCenterContinueActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "", "bindEvent", "()V", "", "getTopBarTitle", "()Ljava/lang/String;", "", "getLayoutId", "()I", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class NewsCenterContinueActivity extends BaseActivity {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    public static List<? extends MsgListBean> itemData;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0010\u0010\u0011J%\u0010\b\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u00022\u000e\u0010\u0006\u001a\n\u0012\u0004\u0012\u00020\u0005\u0018\u00010\u0004¢\u0006\u0004\b\b\u0010\tR(\u0010\n\u001a\b\u0012\u0004\u0012\u00020\u00050\u00048\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000f¨\u0006\u0012"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/chat/NewsCenterContinueActivity$Companion;", "", "Landroid/content/Context;", "context", "", "Lcom/jbzd/media/movecartoons/bean/response/MsgListBean;", "data", "", "start", "(Landroid/content/Context;Ljava/util/List;)V", "itemData", "Ljava/util/List;", "getItemData", "()Ljava/util/List;", "setItemData", "(Ljava/util/List;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final List<MsgListBean> getItemData() {
            List list = NewsCenterContinueActivity.itemData;
            if (list != null) {
                return list;
            }
            Intrinsics.throwUninitializedPropertyAccessException("itemData");
            throw null;
        }

        public final void setItemData(@NotNull List<? extends MsgListBean> list) {
            Intrinsics.checkNotNullParameter(list, "<set-?>");
            NewsCenterContinueActivity.itemData = list;
        }

        public final void start(@NotNull Context context, @Nullable List<? extends MsgListBean> data) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intent intent = new Intent(context, (Class<?>) NewsCenterContinueActivity.class);
            if (data != null) {
                NewsCenterContinueActivity.INSTANCE.setItemData(data);
            }
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        getSupportFragmentManager().beginTransaction().replace(R.id.fragment_container, ExchangeNewsFragment.INSTANCE.newInstance(INSTANCE.getItemData())).commit();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.chat_center_act;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "消息";
    }
}
