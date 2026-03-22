package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemPostCommentBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvPostcommentLikes;

    @NonNull
    public final CircleImageView ivPostCommentUserheder;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvPostCommentContent;

    @NonNull
    public final TextView tvPostCommentReply;

    @NonNull
    public final TextView tvPostCommentTime;

    @NonNull
    public final TextView tvPostUsername;

    private ItemPostCommentBinding(@NonNull LinearLayout linearLayout, @NonNull ImageTextView imageTextView, @NonNull CircleImageView circleImageView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = linearLayout;
        this.itvPostcommentLikes = imageTextView;
        this.ivPostCommentUserheder = circleImageView;
        this.tvPostCommentContent = textView;
        this.tvPostCommentReply = textView2;
        this.tvPostCommentTime = textView3;
        this.tvPostUsername = textView4;
    }

    @NonNull
    public static ItemPostCommentBinding bind(@NonNull View view) {
        int i2 = R.id.itv_postcomment_likes;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_postcomment_likes);
        if (imageTextView != null) {
            i2 = R.id.iv_post_comment_userheder;
            CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.iv_post_comment_userheder);
            if (circleImageView != null) {
                i2 = R.id.tv_post_comment_content;
                TextView textView = (TextView) view.findViewById(R.id.tv_post_comment_content);
                if (textView != null) {
                    i2 = R.id.tv_post_comment_reply;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_post_comment_reply);
                    if (textView2 != null) {
                        i2 = R.id.tv_post_comment_time;
                        TextView textView3 = (TextView) view.findViewById(R.id.tv_post_comment_time);
                        if (textView3 != null) {
                            i2 = R.id.tv_post_username;
                            TextView textView4 = (TextView) view.findViewById(R.id.tv_post_username);
                            if (textView4 != null) {
                                return new ItemPostCommentBinding((LinearLayout) view, imageTextView, circleImageView, textView, textView2, textView3, textView4);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemPostCommentBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemPostCommentBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_post_comment, viewGroup, false);
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
