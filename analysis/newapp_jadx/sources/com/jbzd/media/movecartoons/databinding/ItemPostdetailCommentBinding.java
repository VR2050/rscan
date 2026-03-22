package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemPostdetailCommentBinding implements ViewBinding {

    @NonNull
    public final CircleImageView ivPostdetailCommentUserheder;

    @NonNull
    public final LinearLayout llPostdetailCommentLike;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView tvPostdetailCommentContent;

    @NonNull
    public final TextView tvPostdetailCommentReply;

    @NonNull
    public final TextView tvPostdetailCommentTime;

    @NonNull
    public final TextView tvPostdetailCommentUsername;

    private ItemPostdetailCommentBinding(@NonNull ConstraintLayout constraintLayout, @NonNull CircleImageView circleImageView, @NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = constraintLayout;
        this.ivPostdetailCommentUserheder = circleImageView;
        this.llPostdetailCommentLike = linearLayout;
        this.tvPostdetailCommentContent = textView;
        this.tvPostdetailCommentReply = textView2;
        this.tvPostdetailCommentTime = textView3;
        this.tvPostdetailCommentUsername = textView4;
    }

    @NonNull
    public static ItemPostdetailCommentBinding bind(@NonNull View view) {
        int i2 = R.id.iv_postdetail_comment_userheder;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.iv_postdetail_comment_userheder);
        if (circleImageView != null) {
            i2 = R.id.ll_postdetail_comment_like;
            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_postdetail_comment_like);
            if (linearLayout != null) {
                i2 = R.id.tv_postdetail_comment_content;
                TextView textView = (TextView) view.findViewById(R.id.tv_postdetail_comment_content);
                if (textView != null) {
                    i2 = R.id.tv_postdetail_comment_reply;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_postdetail_comment_reply);
                    if (textView2 != null) {
                        i2 = R.id.tv_postdetail_comment_time;
                        TextView textView3 = (TextView) view.findViewById(R.id.tv_postdetail_comment_time);
                        if (textView3 != null) {
                            i2 = R.id.tv_postdetail_comment_username;
                            TextView textView4 = (TextView) view.findViewById(R.id.tv_postdetail_comment_username);
                            if (textView4 != null) {
                                return new ItemPostdetailCommentBinding((ConstraintLayout) view, circleImageView, linearLayout, textView, textView2, textView3, textView4);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemPostdetailCommentBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemPostdetailCommentBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_postdetail_comment, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public ConstraintLayout getRoot() {
        return this.rootView;
    }
}
