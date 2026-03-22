package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.widget.NestedScrollView;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActPostDetailsBinding implements ViewBinding {

    @NonNull
    public final DialogInputCommentBinding llBottomTool;

    @NonNull
    public final LinearLayout llMicrotanotItem;

    @NonNull
    public final ImageTextView llNodataComment;

    @NonNull
    public final LinearLayout llPostdetailCommentLoading;

    @NonNull
    public final ProgressBar progressComment;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final RecyclerView rvPostComments;

    @NonNull
    public final NestedScrollView srollPostdetail;

    @NonNull
    public final TextView tvCommentLoadstate;

    @NonNull
    public final TextView tvPostdetailComment;

    private ActPostDetailsBinding(@NonNull FrameLayout frameLayout, @NonNull DialogInputCommentBinding dialogInputCommentBinding, @NonNull LinearLayout linearLayout, @NonNull ImageTextView imageTextView, @NonNull LinearLayout linearLayout2, @NonNull ProgressBar progressBar, @NonNull RecyclerView recyclerView, @NonNull NestedScrollView nestedScrollView, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = frameLayout;
        this.llBottomTool = dialogInputCommentBinding;
        this.llMicrotanotItem = linearLayout;
        this.llNodataComment = imageTextView;
        this.llPostdetailCommentLoading = linearLayout2;
        this.progressComment = progressBar;
        this.rvPostComments = recyclerView;
        this.srollPostdetail = nestedScrollView;
        this.tvCommentLoadstate = textView;
        this.tvPostdetailComment = textView2;
    }

    @NonNull
    public static ActPostDetailsBinding bind(@NonNull View view) {
        int i2 = R.id.ll_bottom_tool;
        View findViewById = view.findViewById(R.id.ll_bottom_tool);
        if (findViewById != null) {
            DialogInputCommentBinding bind = DialogInputCommentBinding.bind(findViewById);
            i2 = R.id.ll_microtanot_item;
            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_microtanot_item);
            if (linearLayout != null) {
                i2 = R.id.ll_nodata_comment;
                ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.ll_nodata_comment);
                if (imageTextView != null) {
                    i2 = R.id.ll_postdetail_comment_loading;
                    LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_postdetail_comment_loading);
                    if (linearLayout2 != null) {
                        i2 = R.id.progress_comment;
                        ProgressBar progressBar = (ProgressBar) view.findViewById(R.id.progress_comment);
                        if (progressBar != null) {
                            i2 = R.id.rv_post_comments;
                            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_post_comments);
                            if (recyclerView != null) {
                                i2 = R.id.sroll_postdetail;
                                NestedScrollView nestedScrollView = (NestedScrollView) view.findViewById(R.id.sroll_postdetail);
                                if (nestedScrollView != null) {
                                    i2 = R.id.tv_comment_loadstate;
                                    TextView textView = (TextView) view.findViewById(R.id.tv_comment_loadstate);
                                    if (textView != null) {
                                        i2 = R.id.tv_postdetail_comment;
                                        TextView textView2 = (TextView) view.findViewById(R.id.tv_postdetail_comment);
                                        if (textView2 != null) {
                                            return new ActPostDetailsBinding((FrameLayout) view, bind, linearLayout, imageTextView, linearLayout2, progressBar, recyclerView, nestedScrollView, textView, textView2);
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
    public static ActPostDetailsBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActPostDetailsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_post_details, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
