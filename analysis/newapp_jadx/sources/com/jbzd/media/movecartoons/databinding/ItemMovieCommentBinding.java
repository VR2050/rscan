package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemMovieCommentBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvComment;

    @NonNull
    public final ImageTextView itvLove;

    @NonNull
    public final TextView ivCenterPlayicon;

    @NonNull
    public final ImageView ivHead;

    @NonNull
    public final ImageView ivRights;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvInner;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvMore;

    @NonNull
    public final TextView tvReward;

    @NonNull
    public final TextView tvTime;

    private ItemMovieCommentBinding(@NonNull LinearLayout linearLayout, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull RecyclerView recyclerView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5) {
        this.rootView = linearLayout;
        this.itvComment = imageTextView;
        this.itvLove = imageTextView2;
        this.ivCenterPlayicon = textView;
        this.ivHead = imageView;
        this.ivRights = imageView2;
        this.rvInner = recyclerView;
        this.tvDesc = textView2;
        this.tvMore = textView3;
        this.tvReward = textView4;
        this.tvTime = textView5;
    }

    @NonNull
    public static ItemMovieCommentBinding bind(@NonNull View view) {
        int i2 = R.id.itvComment;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itvComment);
        if (imageTextView != null) {
            i2 = R.id.itvLove;
            ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itvLove);
            if (imageTextView2 != null) {
                i2 = R.id.iv_center_playicon;
                TextView textView = (TextView) view.findViewById(R.id.iv_center_playicon);
                if (textView != null) {
                    i2 = R.id.ivHead;
                    ImageView imageView = (ImageView) view.findViewById(R.id.ivHead);
                    if (imageView != null) {
                        i2 = R.id.ivRights;
                        ImageView imageView2 = (ImageView) view.findViewById(R.id.ivRights);
                        if (imageView2 != null) {
                            i2 = R.id.rv_inner;
                            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_inner);
                            if (recyclerView != null) {
                                i2 = R.id.tvDesc;
                                TextView textView2 = (TextView) view.findViewById(R.id.tvDesc);
                                if (textView2 != null) {
                                    i2 = R.id.tvMore;
                                    TextView textView3 = (TextView) view.findViewById(R.id.tvMore);
                                    if (textView3 != null) {
                                        i2 = R.id.tvReward;
                                        TextView textView4 = (TextView) view.findViewById(R.id.tvReward);
                                        if (textView4 != null) {
                                            i2 = R.id.tvTime;
                                            TextView textView5 = (TextView) view.findViewById(R.id.tvTime);
                                            if (textView5 != null) {
                                                return new ItemMovieCommentBinding((LinearLayout) view, imageTextView, imageTextView2, textView, imageView, imageView2, recyclerView, textView2, textView3, textView4, textView5);
                                            }
                                        }
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
    public static ItemMovieCommentBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemMovieCommentBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_movie_comment, viewGroup, false);
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
