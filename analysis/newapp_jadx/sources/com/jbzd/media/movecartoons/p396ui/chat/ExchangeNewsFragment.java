package com.jbzd.media.movecartoons.p396ui.chat;

import android.content.Context;
import android.graphics.Color;
import android.text.TextUtils;
import android.text.style.AbsoluteSizeSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.UnderlineSpan;
import android.view.View;
import android.widget.ImageView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.MsgListBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.qnmd.adnnm.da0yzo.R;
import io.github.armcha.autolink.AutoLinkTextView;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p143g.p144a.C1558h;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;
import p379c.p380a.InterfaceC3053d1;
import p429g.p430a.p431a.p432a.C4326a;
import p429g.p430a.p431a.p432a.C4330e;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u0000 \u00112\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u0011B\u0007¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u001f\u0010\n\u001a\u00020\t2\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u0011\u0010\r\u001a\u0004\u0018\u00010\fH\u0016¢\u0006\u0004\b\r\u0010\u000e¨\u0006\u0012"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/chat/ExchangeNewsFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/MsgListBean;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/MsgListBean;)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ExchangeNewsFragment extends BaseListFragment<MsgListBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    public static List<? extends MsgListBean> itemData;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000e\u0010\u000fJ\u001b\u0010\u0006\u001a\u00020\u00052\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002¢\u0006\u0004\b\u0006\u0010\u0007R(\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00030\u00028\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\b\u0010\t\u001a\u0004\b\n\u0010\u000b\"\u0004\b\f\u0010\r¨\u0006\u0010"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/chat/ExchangeNewsFragment$Companion;", "", "", "Lcom/jbzd/media/movecartoons/bean/response/MsgListBean;", "data", "Lcom/jbzd/media/movecartoons/ui/chat/ExchangeNewsFragment;", "newInstance", "(Ljava/util/List;)Lcom/jbzd/media/movecartoons/ui/chat/ExchangeNewsFragment;", "itemData", "Ljava/util/List;", "getItemData", "()Ljava/util/List;", "setItemData", "(Ljava/util/List;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final List<MsgListBean> getItemData() {
            List list = ExchangeNewsFragment.itemData;
            if (list != null) {
                return list;
            }
            Intrinsics.throwUninitializedPropertyAccessException("itemData");
            throw null;
        }

        @NotNull
        public final ExchangeNewsFragment newInstance(@NotNull List<? extends MsgListBean> data) {
            Intrinsics.checkNotNullParameter(data, "data");
            ExchangeNewsFragment exchangeNewsFragment = new ExchangeNewsFragment();
            exchangeNewsFragment.getAdapter().addData(data);
            return exchangeNewsFragment;
        }

        public final void setItemData(@NotNull List<? extends MsgListBean> list) {
            Intrinsics.checkNotNullParameter(list, "<set-?>");
            ExchangeNewsFragment.itemData = list;
        }
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_msglist_continue;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        View view = getView();
        ((SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout))).setRefreshing(false);
        return null;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull MsgListBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        ImageView imageView = (ImageView) helper.m3912b(R.id.civ_head);
        C2852c m2455a2 = C2354n.m2455a2(requireContext());
        String str = item.headico;
        if (str == null) {
            str = "";
        }
        C1558h mo770c = m2455a2.mo770c();
        mo770c.mo763X(str);
        ((C2851b) mo770c).m3295i0().m757R(imageView);
        String str2 = item.time_label;
        if (str2 == null) {
            str2 = "";
        }
        helper.m3919i(R.id.tv_time, str2);
        String str3 = item.title;
        helper.m3919i(R.id.tv_name, str3 != null ? str3 : "");
        AutoLinkTextView autoLinkTextView = (AutoLinkTextView) helper.m3912b(R.id.tv_contentPre);
        C4330e c4330e = new C4330e("(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]");
        autoLinkTextView.m4937a(c4330e);
        autoLinkTextView.m4938b(c4330e, new ForegroundColorSpan(Color.argb(255, 26, 115, 232)), new AbsoluteSizeSpan(15, true), new UnderlineSpan());
        autoLinkTextView.m4939c(new Function1<C4326a, Unit>() { // from class: com.jbzd.media.movecartoons.ui.chat.ExchangeNewsFragment$bindItem$1$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(C4326a c4326a) {
                invoke2(c4326a);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull C4326a it) {
                Intrinsics.checkNotNullParameter(it, "it");
                C0840d.a aVar = C0840d.f235a;
                Context requireContext = ExchangeNewsFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                C0840d.a.m174d(aVar, requireContext, it.f11174c, null, null, 12);
            }
        });
        autoLinkTextView.setText(TextUtils.isEmpty(item.content) ^ true ? item.content : "暂无消息");
    }
}
