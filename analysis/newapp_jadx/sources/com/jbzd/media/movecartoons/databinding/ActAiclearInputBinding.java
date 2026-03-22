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
public final class ActAiclearInputBinding implements ViewBinding {

    @NonNull
    public final TextView btnSubmitAiclear;

    @NonNull
    public final ConstraintLayout clDescription;

    @NonNull
    public final ConstraintLayout clMedia;

    @NonNull
    public final AppCompatEditText edAiclearInfo;

    @NonNull
    public final TextView ivAiclearMax;

    @NonNull
    public final RadioButton rbAiclearyifuOpen;

    @NonNull
    public final RadioButton rbAiclearyifuPrivate;

    @NonNull
    public final RadioGroup rgClearyifuOpenPersonal;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvImage;

    @NonNull
    public final TextView tvBottomTipsAiclear;

    @NonNull
    public final TextView tvMediaTitle;

    private ActAiclearInputBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull ConstraintLayout constraintLayout, @NonNull ConstraintLayout constraintLayout2, @NonNull AppCompatEditText appCompatEditText, @NonNull TextView textView2, @NonNull RadioButton radioButton, @NonNull RadioButton radioButton2, @NonNull RadioGroup radioGroup, @NonNull RecyclerView recyclerView, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = linearLayout;
        this.btnSubmitAiclear = textView;
        this.clDescription = constraintLayout;
        this.clMedia = constraintLayout2;
        this.edAiclearInfo = appCompatEditText;
        this.ivAiclearMax = textView2;
        this.rbAiclearyifuOpen = radioButton;
        this.rbAiclearyifuPrivate = radioButton2;
        this.rgClearyifuOpenPersonal = radioGroup;
        this.rvImage = recyclerView;
        this.tvBottomTipsAiclear = textView3;
        this.tvMediaTitle = textView4;
    }

    @NonNull
    public static ActAiclearInputBinding bind(@NonNull View view) {
        int i2 = R.id.btn_submit_aiclear;
        TextView textView = (TextView) view.findViewById(R.id.btn_submit_aiclear);
        if (textView != null) {
            i2 = R.id.cl_description;
            ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.cl_description);
            if (constraintLayout != null) {
                i2 = R.id.cl_media;
                ConstraintLayout constraintLayout2 = (ConstraintLayout) view.findViewById(R.id.cl_media);
                if (constraintLayout2 != null) {
                    i2 = R.id.ed_aiclear_info;
                    AppCompatEditText appCompatEditText = (AppCompatEditText) view.findViewById(R.id.ed_aiclear_info);
                    if (appCompatEditText != null) {
                        i2 = R.id.iv_aiclear_max;
                        TextView textView2 = (TextView) view.findViewById(R.id.iv_aiclear_max);
                        if (textView2 != null) {
                            i2 = R.id.rb_aiclearyifu_open;
                            RadioButton radioButton = (RadioButton) view.findViewById(R.id.rb_aiclearyifu_open);
                            if (radioButton != null) {
                                i2 = R.id.rb_aiclearyifu_private;
                                RadioButton radioButton2 = (RadioButton) view.findViewById(R.id.rb_aiclearyifu_private);
                                if (radioButton2 != null) {
                                    i2 = R.id.rg_clearyifu_open_personal;
                                    RadioGroup radioGroup = (RadioGroup) view.findViewById(R.id.rg_clearyifu_open_personal);
                                    if (radioGroup != null) {
                                        i2 = R.id.rv_image;
                                        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_image);
                                        if (recyclerView != null) {
                                            i2 = R.id.tv_bottom_tips_aiclear;
                                            TextView textView3 = (TextView) view.findViewById(R.id.tv_bottom_tips_aiclear);
                                            if (textView3 != null) {
                                                i2 = R.id.tv_media_title;
                                                TextView textView4 = (TextView) view.findViewById(R.id.tv_media_title);
                                                if (textView4 != null) {
                                                    return new ActAiclearInputBinding((LinearLayout) view, textView, constraintLayout, constraintLayout2, appCompatEditText, textView2, radioButton, radioButton2, radioGroup, recyclerView, textView3, textView4);
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
    public static ActAiclearInputBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActAiclearInputBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_aiclear_input, viewGroup, false);
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
