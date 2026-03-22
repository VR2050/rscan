package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
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
public final class ActPostAicanvasBinding implements ViewBinding {

    @NonNull
    public final TextView btnSubmitAicanvas;

    @NonNull
    public final ConstraintLayout clAdd;

    @NonNull
    public final ConstraintLayout clDescription;

    @NonNull
    public final ConstraintLayout clMedia;

    @NonNull
    public final AppCompatEditText edPostopicPrice;

    @NonNull
    public final AppCompatEditText etAicanvasContent;

    @NonNull
    public final AppCompatEditText etInputNumber;

    @NonNull
    public final RadioButton rbAiclearOpen;

    @NonNull
    public final RadioButton rbAiclearPersonal;

    @NonNull
    public final RadioGroup rgPosttypeOpenPersonal;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvImageBase;

    @NonNull
    public final TextView tvAicanvasBottomtips;

    @NonNull
    public final TextView tvAichangefaceBase;

    @NonNull
    public final TextView tvMediaTitle;

    @NonNull
    public final TextView tvOneunitPicNum;

    private ActPostAicanvasBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull ConstraintLayout constraintLayout, @NonNull ConstraintLayout constraintLayout2, @NonNull ConstraintLayout constraintLayout3, @NonNull AppCompatEditText appCompatEditText, @NonNull AppCompatEditText appCompatEditText2, @NonNull AppCompatEditText appCompatEditText3, @NonNull RadioButton radioButton, @NonNull RadioButton radioButton2, @NonNull RadioGroup radioGroup, @NonNull RecyclerView recyclerView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5) {
        this.rootView = linearLayout;
        this.btnSubmitAicanvas = textView;
        this.clAdd = constraintLayout;
        this.clDescription = constraintLayout2;
        this.clMedia = constraintLayout3;
        this.edPostopicPrice = appCompatEditText;
        this.etAicanvasContent = appCompatEditText2;
        this.etInputNumber = appCompatEditText3;
        this.rbAiclearOpen = radioButton;
        this.rbAiclearPersonal = radioButton2;
        this.rgPosttypeOpenPersonal = radioGroup;
        this.rvImageBase = recyclerView;
        this.tvAicanvasBottomtips = textView2;
        this.tvAichangefaceBase = textView3;
        this.tvMediaTitle = textView4;
        this.tvOneunitPicNum = textView5;
    }

    @NonNull
    public static ActPostAicanvasBinding bind(@NonNull View view) {
        int i2 = R.id.btn_submit_aicanvas;
        TextView textView = (TextView) view.findViewById(R.id.btn_submit_aicanvas);
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
                            i2 = R.id.et_aicanvas_content;
                            AppCompatEditText appCompatEditText2 = (AppCompatEditText) view.findViewById(R.id.et_aicanvas_content);
                            if (appCompatEditText2 != null) {
                                i2 = R.id.et_input_number;
                                AppCompatEditText appCompatEditText3 = (AppCompatEditText) view.findViewById(R.id.et_input_number);
                                if (appCompatEditText3 != null) {
                                    i2 = R.id.rb_aiclear_open;
                                    RadioButton radioButton = (RadioButton) view.findViewById(R.id.rb_aiclear_open);
                                    if (radioButton != null) {
                                        i2 = R.id.rb_aiclear_personal;
                                        RadioButton radioButton2 = (RadioButton) view.findViewById(R.id.rb_aiclear_personal);
                                        if (radioButton2 != null) {
                                            i2 = R.id.rg_posttype_open_personal;
                                            RadioGroup radioGroup = (RadioGroup) view.findViewById(R.id.rg_posttype_open_personal);
                                            if (radioGroup != null) {
                                                i2 = R.id.rv_image_base;
                                                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_image_base);
                                                if (recyclerView != null) {
                                                    i2 = R.id.tv_aicanvas_bottomtips;
                                                    TextView textView2 = (TextView) view.findViewById(R.id.tv_aicanvas_bottomtips);
                                                    if (textView2 != null) {
                                                        i2 = R.id.tv_aichangeface_base;
                                                        TextView textView3 = (TextView) view.findViewById(R.id.tv_aichangeface_base);
                                                        if (textView3 != null) {
                                                            i2 = R.id.tv_media_title;
                                                            TextView textView4 = (TextView) view.findViewById(R.id.tv_media_title);
                                                            if (textView4 != null) {
                                                                i2 = R.id.tv_oneunit_pic_num;
                                                                TextView textView5 = (TextView) view.findViewById(R.id.tv_oneunit_pic_num);
                                                                if (textView5 != null) {
                                                                    return new ActPostAicanvasBinding((LinearLayout) view, textView, constraintLayout, constraintLayout2, constraintLayout3, appCompatEditText, appCompatEditText2, appCompatEditText3, radioButton, radioButton2, radioGroup, recyclerView, textView2, textView3, textView4, textView5);
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
    public static ActPostAicanvasBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActPostAicanvasBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_post_aicanvas, viewGroup, false);
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
