package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.button.MaterialButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogLayoutBinding implements ViewBinding {

    @NonNull
    public final TextView btnBottomMenu;

    @NonNull
    public final MaterialButton btnNegative;

    @NonNull
    public final MaterialButton btnPositive;

    @NonNull
    public final MaterialButton btnPositive2;

    @NonNull
    public final EditText edit;

    @NonNull
    public final LinearLayout llButtons;

    @NonNull
    public final RelativeLayout rlEdit;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final TextView tvMsg;

    @NonNull
    public final TextView tvSubTitle;

    @NonNull
    public final TextView tvTitle;

    private DialogLayoutBinding(@NonNull RelativeLayout relativeLayout, @NonNull TextView textView, @NonNull MaterialButton materialButton, @NonNull MaterialButton materialButton2, @NonNull MaterialButton materialButton3, @NonNull EditText editText, @NonNull LinearLayout linearLayout, @NonNull RelativeLayout relativeLayout2, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = relativeLayout;
        this.btnBottomMenu = textView;
        this.btnNegative = materialButton;
        this.btnPositive = materialButton2;
        this.btnPositive2 = materialButton3;
        this.edit = editText;
        this.llButtons = linearLayout;
        this.rlEdit = relativeLayout2;
        this.tvMsg = textView2;
        this.tvSubTitle = textView3;
        this.tvTitle = textView4;
    }

    @NonNull
    public static DialogLayoutBinding bind(@NonNull View view) {
        int i2 = R.id.btn_bottom_menu;
        TextView textView = (TextView) view.findViewById(R.id.btn_bottom_menu);
        if (textView != null) {
            i2 = R.id.btn_negative;
            MaterialButton materialButton = (MaterialButton) view.findViewById(R.id.btn_negative);
            if (materialButton != null) {
                i2 = R.id.btn_positive;
                MaterialButton materialButton2 = (MaterialButton) view.findViewById(R.id.btn_positive);
                if (materialButton2 != null) {
                    i2 = R.id.btn_positive2;
                    MaterialButton materialButton3 = (MaterialButton) view.findViewById(R.id.btn_positive2);
                    if (materialButton3 != null) {
                        i2 = R.id.edit;
                        EditText editText = (EditText) view.findViewById(R.id.edit);
                        if (editText != null) {
                            i2 = R.id.ll_buttons;
                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_buttons);
                            if (linearLayout != null) {
                                i2 = R.id.rl_edit;
                                RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_edit);
                                if (relativeLayout != null) {
                                    i2 = R.id.tv_msg;
                                    TextView textView2 = (TextView) view.findViewById(R.id.tv_msg);
                                    if (textView2 != null) {
                                        i2 = R.id.tv_subTitle;
                                        TextView textView3 = (TextView) view.findViewById(R.id.tv_subTitle);
                                        if (textView3 != null) {
                                            i2 = R.id.tv_title;
                                            TextView textView4 = (TextView) view.findViewById(R.id.tv_title);
                                            if (textView4 != null) {
                                                return new DialogLayoutBinding((RelativeLayout) view, textView, materialButton, materialButton2, materialButton3, editText, linearLayout, relativeLayout, textView2, textView3, textView4);
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
    public static DialogLayoutBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_layout, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RelativeLayout getRoot() {
        return this.rootView;
    }
}
