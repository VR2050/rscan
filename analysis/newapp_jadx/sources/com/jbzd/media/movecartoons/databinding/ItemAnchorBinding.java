package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemAnchorBinding implements ViewBinding {

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    public final LinearLayout llAnchor;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvLongVideos;

    @NonNull
    public final RecyclerView rvShortVideos;

    @NonNull
    public final TextView tvAnchorName;

    @NonNull
    public final TextView tvTips;

    @NonNull
    public final TextView tvType;

    @NonNull
    public final TextView tvWorksNum;

    private ItemAnchorBinding(@NonNull LinearLayout linearLayout, @NonNull CircleImageView circleImageView, @NonNull LinearLayout linearLayout2, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = linearLayout;
        this.civHead = circleImageView;
        this.llAnchor = linearLayout2;
        this.rvLongVideos = recyclerView;
        this.rvShortVideos = recyclerView2;
        this.tvAnchorName = textView;
        this.tvTips = textView2;
        this.tvType = textView3;
        this.tvWorksNum = textView4;
    }

    @NonNull
    public static ItemAnchorBinding bind(@NonNull View view) {
        int i2 = R.id.civ_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
        if (circleImageView != null) {
            i2 = R.id.ll_anchor;
            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_anchor);
            if (linearLayout != null) {
                i2 = R.id.rv_longVideos;
                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_longVideos);
                if (recyclerView != null) {
                    i2 = R.id.rv_shortVideos;
                    RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_shortVideos);
                    if (recyclerView2 != null) {
                        i2 = R.id.tv_anchorName;
                        TextView textView = (TextView) view.findViewById(R.id.tv_anchorName);
                        if (textView != null) {
                            i2 = R.id.tv_tips;
                            TextView textView2 = (TextView) view.findViewById(R.id.tv_tips);
                            if (textView2 != null) {
                                i2 = R.id.tv_type;
                                TextView textView3 = (TextView) view.findViewById(R.id.tv_type);
                                if (textView3 != null) {
                                    i2 = R.id.tv_worksNum;
                                    TextView textView4 = (TextView) view.findViewById(R.id.tv_worksNum);
                                    if (textView4 != null) {
                                        return new ItemAnchorBinding((LinearLayout) view, circleImageView, linearLayout, recyclerView, recyclerView2, textView, textView2, textView3, textView4);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemAnchorBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemAnchorBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_anchor, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
