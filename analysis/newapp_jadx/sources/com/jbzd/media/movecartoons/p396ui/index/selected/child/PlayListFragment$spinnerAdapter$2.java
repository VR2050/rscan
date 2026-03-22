package com.jbzd.media.movecartoons.p396ui.index.selected.child;

import android.content.SharedPreferences;
import android.view.View;
import android.widget.PopupWindow;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.event.EventLine;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment$spinnerAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p476m.p496b.p497a.C4909c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment$spinnerAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment$spinnerAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PlayListFragment$spinnerAdapter$2 extends Lambda implements Function0<C37851> {
    public final /* synthetic */ PlayListFragment this$0;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000%\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0006*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u000b\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\t¢\u0006\u0004\b\u000b\u0010\fJ\r\u0010\r\u001a\u00020\u0002¢\u0006\u0004\b\r\u0010\u000e¨\u0006\u000f"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment$spinnerAdapter$2$1", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean$PlayLinksBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean$PlayLinksBean;)V", "", "position", "setSelectedPosition", "(I)V", "getSelectedItem", "()Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean$PlayLinksBean;", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    /* renamed from: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$spinnerAdapter$2$1 */
    public static final class C37851 extends BaseQuickAdapter<VideoDetailBean.PlayLinksBean, BaseViewHolder> {
        public final /* synthetic */ PlayListFragment this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C37851(PlayListFragment playListFragment) {
            super(R.layout.item_spinner, null, 2, null);
            this.this$0 = playListFragment;
        }

        @NotNull
        public final VideoDetailBean.PlayLinksBean getSelectedItem() {
            return getData().get(this.this$0.getMSelectP());
        }

        public final void setSelectedPosition(int position) {
            if (this.this$0.getMSelectP() != position) {
                String value = getData().get(position).f9995id;
                Intrinsics.checkNotNullExpressionValue(value, "data[position].id");
                Intrinsics.checkNotNullParameter(value, "id");
                Intrinsics.checkNotNullParameter("default_line", "key");
                Intrinsics.checkNotNullParameter(value, "value");
                ApplicationC2828a applicationC2828a = C2827a.f7670a;
                if (applicationC2828a == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("context");
                    throw null;
                }
                SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
                Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
                SharedPreferences.Editor editor = sharedPreferences.edit();
                Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
                editor.putString("default_line", value);
                editor.commit();
                this.this$0.setMSelectP(position);
                this.this$0.getLinkName().setValue(getData().get(this.this$0.getMSelectP()).name);
                if (Intrinsics.areEqual(this.this$0.getAdapter().getData().get(this.this$0.getCurrentVideoPosition()).play_error_type, "none")) {
                    this.this$0.getLink().setValue(getData().get(this.this$0.getMSelectP()).m3u8_url);
                } else {
                    this.this$0.getLink().setValue(getData().get(this.this$0.getMSelectP()).preview_m3u8_url);
                }
                notifyDataSetChanged();
                C4909c.m5569b().m5574g(new EventLine(this.this$0.getLinkName().getValue(), this.this$0.getLink().getValue()));
            }
        }

        @Override // com.chad.library.adapter.base.BaseQuickAdapter
        public void convert(@NotNull BaseViewHolder helper, @NotNull VideoDetailBean.PlayLinksBean item) {
            Intrinsics.checkNotNullParameter(helper, "helper");
            Intrinsics.checkNotNullParameter(item, "item");
            PlayListFragment playListFragment = this.this$0;
            helper.m3919i(R.id.tv_title, item.name);
            if (helper.getAdapterPosition() == playListFragment.getMSelectP()) {
                helper.m3920j(R.id.tv_title, playListFragment.getResources().getColor(R.color.color_ff6a00));
            } else {
                helper.m3920j(R.id.tv_title, playListFragment.getResources().getColor(R.color.black));
            }
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public PlayListFragment$spinnerAdapter$2(PlayListFragment playListFragment) {
        super(0);
        this.this$0 = playListFragment;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5853invoke$lambda2$lambda1(final C37851 this_apply, final PlayListFragment this$0, BaseQuickAdapter adapter, View noName_1, int i2) {
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(noName_1, "$noName_1");
        this_apply.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.m.a.h
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i3) {
                PlayListFragment$spinnerAdapter$2.m5854invoke$lambda2$lambda1$lambda0(PlayListFragment$spinnerAdapter$2.C37851.this, this$0, baseQuickAdapter, view, i3);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-2$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5854invoke$lambda2$lambda1$lambda0(C37851 this_apply, PlayListFragment this$0, BaseQuickAdapter adapter, View noName_1, int i2) {
        PopupWindow popupWindow;
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(noName_1, "$noName_1");
        this_apply.setSelectedPosition(i2);
        popupWindow = this$0.popWindow;
        if (popupWindow == null) {
            return;
        }
        popupWindow.dismiss();
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C37851 invoke() {
        final C37851 c37851 = new C37851(this.this$0);
        final PlayListFragment playListFragment = this.this$0;
        c37851.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.m.a.g
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                PlayListFragment$spinnerAdapter$2.m5853invoke$lambda2$lambda1(PlayListFragment$spinnerAdapter$2.C37851.this, playListFragment, baseQuickAdapter, view, i2);
            }
        });
        return c37851;
    }
}
