package im.uwrkaxlmjj.ui.dialogs;

import android.app.Activity;
import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.ItemTouchHelper;
import com.bigkoo.pickerview.configure.PickerOptions;
import com.bigkoo.pickerview.listener.CustomListener;
import com.bigkoo.pickerview.listener.OnOptionsSelectListener;
import com.bigkoo.pickerview.view.OptionsPickerView;
import com.contrarywind.view.WheelView;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import java.util.Calendar;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class OptionsWheelPickerDialog<T> extends BottomSheet {
    private Builder<T> mBuilder;

    public OptionsWheelPickerDialog(Context context, Builder<T> builder, int backgroundType) {
        super(context, R.plurals.TransparentDialog);
        this.mBuilder = builder;
        init(context, false, backgroundType);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected void init(Context context, boolean needFocus, int backgroundType) {
        super.init(context, needFocus, backgroundType);
        setApplyTopPadding(false);
        setApplyBottomPadding(false);
        setBackgroundColor(Theme.getColor(Theme.key_dialogBackgroundGray));
        OptionsPickerView<T> mTimePickerView = new OptionsPickerView<T>(this.mBuilder.mPickerOptions) { // from class: im.uwrkaxlmjj.ui.dialogs.OptionsWheelPickerDialog.1
            @Override // com.bigkoo.pickerview.view.BasePickerView
            public void dismiss() {
                OptionsWheelPickerDialog.this.dismiss();
            }
        };
        mTimePickerView.setPicker(this.mBuilder.options1Items, this.mBuilder.options2Items, this.mBuilder.options3Items);
        mTimePickerView.setSelectOptions(((Builder) this.mBuilder).option1, ((Builder) this.mBuilder).option2, ((Builder) this.mBuilder).option3);
        View customView = mTimePickerView.getDialogContainerLayout();
        customView.findViewById(R.attr.rv_topbar).setLayoutParams(LayoutHelper.createLinear(-1, 60));
        customView.findViewById(R.attr.optionspicker).setLayoutParams(LayoutHelper.createLinear(-1, ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION));
        setCustomView(customView);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithSwipe() {
        return false;
    }

    public static <T> Builder<T> getDefaultBuilder(Activity context, OnOptionsSelectListener listener) {
        Builder<T> builder = new Builder<>(context, listener);
        builder.setBgColor(0).setSubCalSize(16).setCancelColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3)).setCancelText(LocaleController.getString(R.string.Cancel)).setTitleBgColor(0).setSubmitColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText)).setSubmitText(LocaleController.getString(R.string.Confirm)).setDividerColor(Theme.getColor(Theme.key_divider)).setTextColorCenter(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText)).setTextColorOut(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3)).setContentTextSize(16).setOutSideColor(0).setOutSideCancelable(false).isDialog(false);
        builder.mPickerOptions.itemsVisibleCount = 3;
        builder.mPickerOptions.lineSpacingMultiplier = 3.5f;
        return builder;
    }

    public static class Builder<T> {
        public PickerOptions mPickerOptions;
        private int option1;
        private int option2;
        private int option3;
        public List<T> options1Items;
        public List<List<T>> options2Items;
        public List<List<List<T>>> options3Items;

        public Builder(Context context, OnOptionsSelectListener listener) {
            PickerOptions pickerOptions = new PickerOptions(1);
            this.mPickerOptions = pickerOptions;
            pickerOptions.context = context;
            this.mPickerOptions.optionsSelectListener = listener;
        }

        public Builder<T> setGravity(int gravity) {
            this.mPickerOptions.textGravity = gravity;
            return this;
        }

        public Builder<T> addOnCancelClickListener(View.OnClickListener cancelListener) {
            this.mPickerOptions.cancelListener = cancelListener;
            return this;
        }

        public Builder<T> setSubmitText(String textContentConfirm) {
            this.mPickerOptions.textContentConfirm = textContentConfirm;
            return this;
        }

        public Builder<T> isDialog(boolean isDialog) {
            this.mPickerOptions.isDialog = isDialog;
            return this;
        }

        public Builder<T> setCancelText(String textContentCancel) {
            this.mPickerOptions.textContentCancel = textContentCancel;
            return this;
        }

        public Builder<T> setTitleText(String textContentTitle) {
            this.mPickerOptions.textContentTitle = textContentTitle;
            return this;
        }

        public Builder<T> setSubmitColor(int textColorConfirm) {
            this.mPickerOptions.textColorConfirm = textColorConfirm;
            return this;
        }

        public Builder<T> setCancelColor(int textColorCancel) {
            this.mPickerOptions.textColorCancel = textColorCancel;
            return this;
        }

        public Builder<T> setDecorView(ViewGroup decorView) {
            this.mPickerOptions.decorView = decorView;
            return this;
        }

        public Builder<T> setBgColor(int bgColorWheel) {
            this.mPickerOptions.bgColorWheel = bgColorWheel;
            return this;
        }

        public Builder<T> setTitleBgColor(int bgColorTitle) {
            this.mPickerOptions.bgColorTitle = bgColorTitle;
            return this;
        }

        public Builder<T> setTitleColor(int textColorTitle) {
            this.mPickerOptions.textColorTitle = textColorTitle;
            return this;
        }

        public Builder<T> setSubCalSize(int textSizeSubmitCancel) {
            this.mPickerOptions.textSizeSubmitCancel = textSizeSubmitCancel;
            return this;
        }

        public Builder<T> setTitleSize(int textSizeTitle) {
            this.mPickerOptions.textSizeTitle = textSizeTitle;
            return this;
        }

        public Builder<T> setContentTextSize(int textSizeContent) {
            this.mPickerOptions.textSizeContent = textSizeContent;
            return this;
        }

        public Builder<T> setItemVisibleCount(int count) {
            this.mPickerOptions.itemsVisibleCount = count;
            return this;
        }

        public Builder<T> isAlphaGradient(boolean isAlphaGradient) {
            this.mPickerOptions.isAlphaGradient = isAlphaGradient;
            return this;
        }

        public Builder<T> setDate(Calendar date) {
            this.mPickerOptions.date = date;
            return this;
        }

        public Builder<T> setLayoutRes(int res, CustomListener customListener) {
            this.mPickerOptions.layoutRes = res;
            this.mPickerOptions.customListener = customListener;
            return this;
        }

        public Builder<T> setLineSpacingMultiplier(float lineSpacingMultiplier) {
            this.mPickerOptions.lineSpacingMultiplier = lineSpacingMultiplier;
            return this;
        }

        public Builder<T> setDividerColor(int dividerColor) {
            this.mPickerOptions.dividerColor = dividerColor;
            return this;
        }

        public Builder<T> setDividerType(WheelView.DividerType dividerType) {
            this.mPickerOptions.dividerType = dividerType;
            return this;
        }

        @Deprecated
        public Builder<T> setBackgroundId(int backgroundId) {
            this.mPickerOptions.outSideColor = backgroundId;
            return this;
        }

        public Builder<T> setOutSideColor(int outSideColor) {
            this.mPickerOptions.outSideColor = outSideColor;
            return this;
        }

        public Builder<T> setTextColorCenter(int textColorCenter) {
            this.mPickerOptions.textColorCenter = textColorCenter;
            return this;
        }

        public Builder<T> setTextColorOut(int textColorOut) {
            this.mPickerOptions.textColorOut = textColorOut;
            return this;
        }

        public Builder<T> isCyclic(boolean cyclic) {
            this.mPickerOptions.cyclic = cyclic;
            return this;
        }

        public Builder<T> setOutSideCancelable(boolean cancelable) {
            this.mPickerOptions.cancelable = cancelable;
            return this;
        }

        public Builder<T> setLunarCalendar(boolean lunarCalendar) {
            this.mPickerOptions.isLunarCalendar = lunarCalendar;
            return this;
        }

        public Builder<T> isCenterLabel(boolean isCenterLabel) {
            this.mPickerOptions.isCenterLabel = isCenterLabel;
            return this;
        }

        public Builder<T> setSelectOptions(int option1) {
            this.option1 = option1;
            return this;
        }

        public Builder<T> setSelectOptions(int option1, int option2) {
            this.option1 = option1;
            this.option2 = option2;
            return this;
        }

        public Builder<T> setSelectOptions(int option1, int option2, int option3) {
            this.option1 = option1;
            this.option2 = option2;
            this.option3 = option3;
            return this;
        }

        public Builder<T> setPicker(List<T> options1Items) {
            this.options1Items = options1Items;
            return this;
        }

        public Builder<T> setPicker(List<T> options1Items, List<List<T>> options2Items) {
            this.options1Items = options1Items;
            this.options2Items = options2Items;
            return this;
        }

        public Builder<T> setPicker(List<T> options1Items, List<List<T>> options2Items, List<List<List<T>>> options3Items) {
            this.options1Items = options1Items;
            this.options2Items = options2Items;
            this.options3Items = options3Items;
            return this;
        }

        public OptionsWheelPickerDialog<T> build() {
            return build(1);
        }

        public OptionsWheelPickerDialog<T> build(int backgroundType) {
            this.mPickerOptions.isDialog = false;
            return new OptionsWheelPickerDialog<>(this.mPickerOptions.context, this, backgroundType);
        }
    }
}
