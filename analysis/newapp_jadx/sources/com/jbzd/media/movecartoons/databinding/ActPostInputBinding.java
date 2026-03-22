package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActPostInputBinding implements ViewBinding {

    @NonNull
    public final TextView btnSubmitAichangefaceVideo;

    @NonNull
    public final ConstraintLayout clAdd;

    @NonNull
    public final ConstraintLayout clDescription;

    @NonNull
    public final ConstraintLayout clMedia;

    @NonNull
    public final AppCompatEditText edPostMoney;

    @NonNull
    public final AppCompatEditText edPostopicTitle;

    @NonNull
    public final FrameLayout errorView;

    @NonNull
    public final AppCompatEditText etAivideochangefaceInfo;

    @NonNull
    public final ImageTextView itvTagsMore;

    @NonNull
    public final LinearLayout llPostCoinSet;

    @NonNull
    public final LinearLayout llPostTitle;

    @NonNull
    public final LinearLayout llPostimage;

    @NonNull
    public final LinearLayout llPosttopicName;

    @NonNull
    public final LinearLayout llPostvideo;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvImage;

    @NonNull
    public final RecyclerView rvVideo;

    @NonNull
    public final TextView tvMediaTitle;

    @NonNull
    public final TextView tvMediaVideoTips;

    @NonNull
    public final TextView tvTagsSelected;

    private ActPostInputBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull ConstraintLayout constraintLayout, @NonNull ConstraintLayout constraintLayout2, @NonNull ConstraintLayout constraintLayout3, @NonNull AppCompatEditText appCompatEditText, @NonNull AppCompatEditText appCompatEditText2, @NonNull FrameLayout frameLayout, @NonNull AppCompatEditText appCompatEditText3, @NonNull ImageTextView imageTextView, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull LinearLayout linearLayout6, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = linearLayout;
        this.btnSubmitAichangefaceVideo = textView;
        this.clAdd = constraintLayout;
        this.clDescription = constraintLayout2;
        this.clMedia = constraintLayout3;
        this.edPostMoney = appCompatEditText;
        this.edPostopicTitle = appCompatEditText2;
        this.errorView = frameLayout;
        this.etAivideochangefaceInfo = appCompatEditText3;
        this.itvTagsMore = imageTextView;
        this.llPostCoinSet = linearLayout2;
        this.llPostTitle = linearLayout3;
        this.llPostimage = linearLayout4;
        this.llPosttopicName = linearLayout5;
        this.llPostvideo = linearLayout6;
        this.rvImage = recyclerView;
        this.rvVideo = recyclerView2;
        this.tvMediaTitle = textView2;
        this.tvMediaVideoTips = textView3;
        this.tvTagsSelected = textView4;
    }

    @NonNull
    public static ActPostInputBinding bind(@NonNull View view) {
        int i2 = R.id.btn_submit_aichangeface_video;
        TextView textView = (TextView) view.findViewById(R.id.btn_submit_aichangeface_video);
        if (textView != null) {
            i2 = R.id.cl_add;
            ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.cl_add);
            if (constraintLayout != null) {
                i2 = R.id.cl_description;
                ConstraintLayout constraintLayout2 = (ConstraintLayout) view.findViewById(R.id.cl_description);
                if (constraintLayout2 != null) {
                    i2 = R.id.cl_media;
                    ConstraintLayout constraintLayout3 = (ConstraintLayout) view.findViewById(R.id.cl_media);
                    if (constraintLayout3 != null) {
                        i2 = R.id.ed_post_money;
                        AppCompatEditText appCompatEditText = (AppCompatEditText) view.findViewById(R.id.ed_post_money);
                        if (appCompatEditText != null) {
                            i2 = R.id.ed_postopic_title;
                            AppCompatEditText appCompatEditText2 = (AppCompatEditText) view.findViewById(R.id.ed_postopic_title);
                            if (appCompatEditText2 != null) {
                                i2 = R.id.error_view;
                                FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.error_view);
                                if (frameLayout != null) {
                                    i2 = R.id.et_aivideochangeface_info;
                                    AppCompatEditText appCompatEditText3 = (AppCompatEditText) view.findViewById(R.id.et_aivideochangeface_info);
                                    if (appCompatEditText3 != null) {
                                        i2 = R.id.itv_tags_more;
                                        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_tags_more);
                                        if (imageTextView != null) {
                                            i2 = R.id.ll_post_coin_set;
                                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_post_coin_set);
                                            if (linearLayout != null) {
                                                i2 = R.id.ll_post_title;
                                                LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_post_title);
                                                if (linearLayout2 != null) {
                                                    i2 = R.id.ll_postimage;
                                                    LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_postimage);
                                                    if (linearLayout3 != null) {
                                                        i2 = R.id.ll_posttopic_name;
                                                        LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_posttopic_name);
                                                        if (linearLayout4 != null) {
                                                            i2 = R.id.ll_postvideo;
                                                            LinearLayout linearLayout5 = (LinearLayout) view.findViewById(R.id.ll_postvideo);
                                                            if (linearLayout5 != null) {
                                                                i2 = R.id.rv_image;
                                                                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_image);
                                                                if (recyclerView != null) {
                                                                    i2 = R.id.rv_video;
                                                                    RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_video);
                                                                    if (recyclerView2 != null) {
                                                                        i2 = R.id.tv_media_title;
                                                                        TextView textView2 = (TextView) view.findViewById(R.id.tv_media_title);
                                                                        if (textView2 != null) {
                                                                            i2 = R.id.tv_media_video_tips;
                                                                            TextView textView3 = (TextView) view.findViewById(R.id.tv_media_video_tips);
                                                                            if (textView3 != null) {
                                                                                i2 = R.id.tv_tags_selected;
                                                                                TextView textView4 = (TextView) view.findViewById(R.id.tv_tags_selected);
                                                                                if (textView4 != null) {
                                                                                    return new ActPostInputBinding((LinearLayout) view, textView, constraintLayout, constraintLayout2, constraintLayout3, appCompatEditText, appCompatEditText2, frameLayout, appCompatEditText3, imageTextView, linearLayout, linearLayout2, linearLayout3, linearLayout4, linearLayout5, recyclerView, recyclerView2, textView2, textView3, textView4);
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
    public static ActPostInputBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActPostInputBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_post_input, viewGroup, false);
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
