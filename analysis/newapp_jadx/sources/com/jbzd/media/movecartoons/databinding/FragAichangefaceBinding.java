package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragAichangefaceBinding implements ViewBinding {

    @NonNull
    public final TextView btnSubmitAichangefaceVideo;

    @NonNull
    public final ConstraintLayout clAdd;

    @NonNull
    public final ConstraintLayout clDescription;

    @NonNull
    public final ConstraintLayout clMedia;

    @NonNull
    public final AppCompatEditText edPostopicPrice;

    @NonNull
    public final AppCompatEditText etAichangefaceInfo;

    @NonNull
    public final RadioButton rbAichangefaceOpen;

    @NonNull
    public final RadioButton rbAichangefacePersonal;

    @NonNull
    public final RadioGroup rgChangefaceOpenPersonal;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final RecyclerView rvImage;

    @NonNull
    public final RecyclerView rvImageBase;

    @NonNull
    public final TextView tvAichangefaceBase;

    @NonNull
    public final TextView tvAichangefaceBasemin;

    @NonNull
    public final TextView tvAichangefaceBottomtips;

    @NonNull
    public final TextView tvAichangefaceMinface;

    @NonNull
    public final TextView tvMediaTitle;

    private FragAichangefaceBinding(@NonNull FrameLayout frameLayout, @NonNull TextView textView, @NonNull ConstraintLayout constraintLayout, @NonNull ConstraintLayout constraintLayout2, @NonNull ConstraintLayout constraintLayout3, @NonNull AppCompatEditText appCompatEditText, @NonNull AppCompatEditText appCompatEditText2, @NonNull RadioButton radioButton, @NonNull RadioButton radioButton2, @NonNull RadioGroup radioGroup, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6) {
        this.rootView = frameLayout;
        this.btnSubmitAichangefaceVideo = textView;
        this.clAdd = constraintLayout;
        this.clDescription = constraintLayout2;
        this.clMedia = constraintLayout3;
        this.edPostopicPrice = appCompatEditText;
        this.etAichangefaceInfo = appCompatEditText2;
        this.rbAichangefaceOpen = radioButton;
        this.rbAichangefacePersonal = radioButton2;
        this.rgChangefaceOpenPersonal = radioGroup;
        this.rvImage = recyclerView;
        this.rvImageBase = recyclerView2;
        this.tvAichangefaceBase = textView2;
        this.tvAichangefaceBasemin = textView3;
        this.tvAichangefaceBottomtips = textView4;
        this.tvAichangefaceMinface = textView5;
        this.tvMediaTitle = textView6;
    }

    @NonNull
    public static FragAichangefaceBinding bind(@NonNull View view) {
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
                        i2 = R.id.ed_postopic_price;
                        AppCompatEditText appCompatEditText = (AppCompatEditText) view.findViewById(R.id.ed_postopic_price);
                        if (appCompatEditText != null) {
                            i2 = R.id.et_aichangeface_info;
                            AppCompatEditText appCompatEditText2 = (AppCompatEditText) view.findViewById(R.id.et_aichangeface_info);
                            if (appCompatEditText2 != null) {
                                i2 = R.id.rb_aichangeface_open;
                                RadioButton radioButton = (RadioButton) view.findViewById(R.id.rb_aichangeface_open);
                                if (radioButton != null) {
                                    i2 = R.id.rb_aichangeface_personal;
                                    RadioButton radioButton2 = (RadioButton) view.findViewById(R.id.rb_aichangeface_personal);
                                    if (radioButton2 != null) {
                                        i2 = R.id.rg_changeface_open_personal;
                                        RadioGroup radioGroup = (RadioGroup) view.findViewById(R.id.rg_changeface_open_personal);
                                        if (radioGroup != null) {
                                            i2 = R.id.rv_image;
                                            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_image);
                                            if (recyclerView != null) {
                                                i2 = R.id.rv_image_base;
                                                RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_image_base);
                                                if (recyclerView2 != null) {
                                                    i2 = R.id.tv_aichangeface_base;
                                                    TextView textView2 = (TextView) view.findViewById(R.id.tv_aichangeface_base);
                                                    if (textView2 != null) {
                                                        i2 = R.id.tv_aichangeface_basemin;
                                                        TextView textView3 = (TextView) view.findViewById(R.id.tv_aichangeface_basemin);
                                                        if (textView3 != null) {
                                                            i2 = R.id.tv_aichangeface_bottomtips;
                                                            TextView textView4 = (TextView) view.findViewById(R.id.tv_aichangeface_bottomtips);
                                                            if (textView4 != null) {
                                                                i2 = R.id.tv_aichangeface_minface;
                                                                TextView textView5 = (TextView) view.findViewById(R.id.tv_aichangeface_minface);
                                                                if (textView5 != null) {
                                                                    i2 = R.id.tv_media_title;
                                                                    TextView textView6 = (TextView) view.findViewById(R.id.tv_media_title);
                                                                    if (textView6 != null) {
                                                                        return new FragAichangefaceBinding((FrameLayout) view, textView, constraintLayout, constraintLayout2, constraintLayout3, appCompatEditText, appCompatEditText2, radioButton, radioButton2, radioGroup, recyclerView, recyclerView2, textView2, textView3, textView4, textView5, textView6);
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
    public static FragAichangefaceBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragAichangefaceBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_aichangeface, viewGroup, false);
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
