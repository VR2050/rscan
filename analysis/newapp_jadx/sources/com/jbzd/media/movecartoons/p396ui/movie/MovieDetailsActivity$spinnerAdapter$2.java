package com.jbzd.media.movecartoons.p396ui.movie;

import android.content.SharedPreferences;
import android.view.View;
import android.widget.PopupWindow;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDescFragment;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity$spinnerAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/movie/MovieDetailsActivity$spinnerAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsActivity$spinnerAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MovieDetailsActivity$spinnerAdapter$2 extends Lambda implements Function0<C38301> {
    public final /* synthetic */ MovieDetailsActivity this$0;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000%\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0006*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u000b\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\t¢\u0006\u0004\b\u000b\u0010\fJ\r\u0010\r\u001a\u00020\u0002¢\u0006\u0004\b\r\u0010\u000e¨\u0006\u000f"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/movie/MovieDetailsActivity$spinnerAdapter$2$1", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean$PlayLinksBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean$PlayLinksBean;)V", "", "position", "setSelectedPosition", "(I)V", "getSelectedItem", "()Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean$PlayLinksBean;", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    /* renamed from: com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$spinnerAdapter$2$1 */
    public static final class C38301 extends BaseQuickAdapter<VideoDetailBean.PlayLinksBean, BaseViewHolder> {
        public final /* synthetic */ MovieDetailsActivity this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C38301(MovieDetailsActivity movieDetailsActivity) {
            super(R.layout.item_spinner, null, 2, null);
            this.this$0 = movieDetailsActivity;
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
                this.this$0.getTv_spinner().setText(getData().get(position).name);
                MovieDescFragment.Companion companion = MovieDescFragment.INSTANCE;
                if (companion.getMVideoDetailBean() != null) {
                    if (Intrinsics.areEqual(companion.getMVideoDetailBean().play_error_type, "none")) {
                        MovieDetailsViewModel viewModel = this.this$0.getViewModel();
                        String str = getData().get(position).m3u8_url;
                        Intrinsics.checkNotNullExpressionValue(str, "data.get(position).m3u8_url");
                        viewModel.setLink(str);
                    } else {
                        MovieDetailsViewModel viewModel2 = this.this$0.getViewModel();
                        String str2 = getData().get(position).preview_m3u8_url;
                        Intrinsics.checkNotNullExpressionValue(str2, "data.get(position).preview_m3u8_url");
                        viewModel2.setLink(str2);
                    }
                    MovieDetailsViewModel viewModel3 = this.this$0.getViewModel();
                    String str3 = getData().get(position).name;
                    Intrinsics.checkNotNullExpressionValue(str3, "data.get(position).name");
                    viewModel3.setLinkName(str3);
                    this.this$0.setMSelectP(position);
                    notifyDataSetChanged();
                }
            }
        }

        @Override // com.chad.library.adapter.base.BaseQuickAdapter
        public void convert(@NotNull BaseViewHolder helper, @NotNull VideoDetailBean.PlayLinksBean item) {
            Intrinsics.checkNotNullParameter(helper, "helper");
            Intrinsics.checkNotNullParameter(item, "item");
            MovieDetailsActivity movieDetailsActivity = this.this$0;
            helper.m3919i(R.id.tv_title, item.name);
            if (helper.getAdapterPosition() == movieDetailsActivity.getMSelectP()) {
                helper.m3920j(R.id.tv_title, movieDetailsActivity.getResources().getColor(R.color.color_ff6a00));
            } else {
                helper.m3920j(R.id.tv_title, movieDetailsActivity.getResources().getColor(R.color.black));
            }
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MovieDetailsActivity$spinnerAdapter$2(MovieDetailsActivity movieDetailsActivity) {
        super(0);
        this.this$0 = movieDetailsActivity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5901invoke$lambda1$lambda0(C38301 this_apply, MovieDetailsActivity this$0, BaseQuickAdapter adapter, View noName_1, int i2) {
        PopupWindow popupWindow;
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(noName_1, "$noName_1");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.VideoDetailBean.PlayLinksBean");
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
    public final C38301 invoke() {
        final C38301 c38301 = new C38301(this.this$0);
        final MovieDetailsActivity movieDetailsActivity = this.this$0;
        c38301.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.i.e0
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                MovieDetailsActivity$spinnerAdapter$2.m5901invoke$lambda1$lambda0(MovieDetailsActivity$spinnerAdapter$2.C38301.this, movieDetailsActivity, baseQuickAdapter, view, i2);
            }
        });
        return c38301;
    }
}
