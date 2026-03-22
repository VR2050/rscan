package com.jbzd.media.movecartoons.p396ui.movie;

import android.annotation.SuppressLint;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import com.jbzd.media.movecartoons.view.text.MyRadioButton;
import com.qnmd.adnnm.da0yzo.R;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0010!\n\u0002\b\u0007\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001!B\u001d\u0012\f\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\u00140\u001b\u0012\u0006\u0010\u0015\u001a\u00020\u0014¢\u0006\u0004\b\u001f\u0010 J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u001f\u0010\f\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\u000b\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\f\u0010\rJ\u001f\u0010\u000e\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u000e\u0010\bJ!\u0010\u0012\u001a\u00020\u00062\u0012\u0010\u0011\u001a\u000e\u0012\u0004\u0012\u00020\u0010\u0012\u0004\u0012\u00020\u00060\u000f¢\u0006\u0004\b\u0012\u0010\u0013J\u0017\u0010\u0016\u001a\u00020\u00062\u0006\u0010\u0015\u001a\u00020\u0014H\u0007¢\u0006\u0004\b\u0016\u0010\u0017J\u000f\u0010\u0018\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0018\u0010\u0019R$\u0010\u0011\u001a\u0010\u0012\u0004\u0012\u00020\u0010\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u000f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0011\u0010\u001aR\u001c\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\u00140\u001b8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001c\u0010\u001dR\u0016\u0010\u0015\u001a\u00020\u00148\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0015\u0010\u001e¨\u0006\""}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/VideoSeparationAdapter;", "Landroidx/recyclerview/widget/RecyclerView$Adapter;", "Lcom/jbzd/media/movecartoons/ui/movie/VideoSeparationAdapter$ViewHolder;", "viewHolder", "", "position", "", "display", "(Lcom/jbzd/media/movecartoons/ui/movie/VideoSeparationAdapter$ViewHolder;I)V", "Landroid/view/ViewGroup;", "viewGroup", "viewType", "onCreateViewHolder", "(Landroid/view/ViewGroup;I)Lcom/jbzd/media/movecartoons/ui/movie/VideoSeparationAdapter$ViewHolder;", "onBindViewHolder", "Lkotlin/Function1;", "Landroid/view/View;", "btnOnCLickListener", "setBtnOnClickListener", "(Lkotlin/jvm/functions/Function1;)V", "", "moveId", "notifyDataSetChangedAndUI", "(Ljava/lang/String;)V", "getItemCount", "()I", "Lkotlin/jvm/functions/Function1;", "", "dataSet", "Ljava/util/List;", "Ljava/lang/String;", "<init>", "(Ljava/util/List;Ljava/lang/String;)V", "ViewHolder", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class VideoSeparationAdapter extends RecyclerView.Adapter<ViewHolder> {

    @Nullable
    private Function1<? super View, Unit> btnOnCLickListener;

    @NotNull
    private final List<String> dataSet;

    @NotNull
    private String moveId;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\b\u001a\u00020\u0007¢\u0006\u0004\b\t\u0010\nR\u0019\u0010\u0003\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0003\u0010\u0004\u001a\u0004\b\u0005\u0010\u0006¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/VideoSeparationAdapter$ViewHolder;", "Landroidx/recyclerview/widget/RecyclerView$ViewHolder;", "Lcom/jbzd/media/movecartoons/view/text/MyRadioButton;", "btnMovieSerials", "Lcom/jbzd/media/movecartoons/view/text/MyRadioButton;", "getBtnMovieSerials", "()Lcom/jbzd/media/movecartoons/view/text/MyRadioButton;", "Landroid/view/View;", "view", "<init>", "(Landroid/view/View;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class ViewHolder extends RecyclerView.ViewHolder {

        @NotNull
        private final MyRadioButton btnMovieSerials;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public ViewHolder(@NotNull View view) {
            super(view);
            Intrinsics.checkNotNullParameter(view, "view");
            View findViewById = view.findViewById(R.id.btn_movie_serials);
            Intrinsics.checkNotNullExpressionValue(findViewById, "view.findViewById(R.id.btn_movie_serials)");
            this.btnMovieSerials = (MyRadioButton) findViewById;
        }

        @NotNull
        public final MyRadioButton getBtnMovieSerials() {
            return this.btnMovieSerials;
        }
    }

    public VideoSeparationAdapter(@NotNull List<String> dataSet, @NotNull String moveId) {
        Intrinsics.checkNotNullParameter(dataSet, "dataSet");
        Intrinsics.checkNotNullParameter(moveId, "moveId");
        this.dataSet = dataSet;
        this.moveId = moveId;
    }

    private final void display(ViewHolder viewHolder, int position) {
        viewHolder.getBtnMovieSerials().setTag(this.dataSet.get(position));
        viewHolder.getBtnMovieSerials().setText(String.valueOf(position + 1));
        viewHolder.getBtnMovieSerials().setChecked(Intrinsics.areEqual(this.moveId, this.dataSet.get(position)));
        C2354n.m2374A(viewHolder.getBtnMovieSerials(), 0L, new Function1<MyRadioButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.VideoSeparationAdapter$display$1$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(MyRadioButton myRadioButton) {
                invoke2(myRadioButton);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull MyRadioButton it) {
                Function1 function1;
                Intrinsics.checkNotNullParameter(it, "it");
                function1 = VideoSeparationAdapter.this.btnOnCLickListener;
                if (function1 == null) {
                    return;
                }
                function1.invoke(it);
            }
        }, 1);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return this.dataSet.size();
    }

    @SuppressLint({"NotifyDataSetChanged"})
    public final void notifyDataSetChangedAndUI(@NotNull String moveId) {
        Intrinsics.checkNotNullParameter(moveId, "moveId");
        this.moveId = moveId;
        notifyDataSetChanged();
    }

    public final void setBtnOnClickListener(@NotNull Function1<? super View, Unit> btnOnCLickListener) {
        Intrinsics.checkNotNullParameter(btnOnCLickListener, "btnOnCLickListener");
        this.btnOnCLickListener = btnOnCLickListener;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(@NotNull ViewHolder viewHolder, int position) {
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        display(viewHolder, position);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    @NotNull
    public ViewHolder onCreateViewHolder(@NotNull ViewGroup viewGroup, int viewType) {
        Intrinsics.checkNotNullParameter(viewGroup, "viewGroup");
        View view = LayoutInflater.from(viewGroup.getContext()).inflate(R.layout.item_movie_detail_serials, viewGroup, false);
        Intrinsics.checkNotNullExpressionValue(view, "view");
        return new ViewHolder(view);
    }
}
