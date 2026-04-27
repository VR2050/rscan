package im.uwrkaxlmjj.ui.hviews;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.os.Build;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.View;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import im.uwrkaxlmjj.messenger.R;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes5.dex */
public class SegmenteView extends RadioGroup {
    private int defaultSelection;
    private boolean equalWidth;
    private String identifier;
    private LinkedHashMap<String, String> itemMap;
    private Context mCtx;
    private OnSelectionChangedListener mListener;
    private int mSdk;
    private ArrayList<RadioButton> options;
    private int selectedColor;
    private int selectedTextColor;
    private RadioGroup.OnCheckedChangeListener selectionChangedlistener;
    private boolean stretch;
    private ColorStateList textColorStateList;
    private int unselectedColor;
    private int unselectedTextColor;

    public interface OnSelectionChangedListener {
        void onItemSelected(int i);
    }

    public SegmenteView(Context context) {
        super(context, null);
        this.selectedColor = Color.parseColor("#FFD63B52");
        this.unselectedColor = 0;
        this.unselectedTextColor = Color.parseColor("#FFD63B52");
        this.defaultSelection = -1;
        this.stretch = false;
        this.selectedTextColor = -1;
        this.equalWidth = false;
        this.identifier = "";
        this.itemMap = new LinkedHashMap<>();
        this.selectionChangedlistener = new RadioGroup.OnCheckedChangeListener() { // from class: im.uwrkaxlmjj.ui.hviews.SegmenteView.1
            @Override // android.widget.RadioGroup.OnCheckedChangeListener
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                View viewById = group.findViewById(checkedId);
                if (viewById.isPressed() && SegmenteView.this.mListener != null) {
                    SegmenteView.this.mListener.onItemSelected(checkedId);
                }
            }
        };
        init(context);
        update();
    }

    public SegmenteView(Context context, AttributeSet attrs) throws Exception {
        super(context, attrs);
        this.selectedColor = Color.parseColor("#FFD63B52");
        this.unselectedColor = 0;
        this.unselectedTextColor = Color.parseColor("#FFD63B52");
        this.defaultSelection = -1;
        this.stretch = false;
        this.selectedTextColor = -1;
        this.equalWidth = false;
        this.identifier = "";
        this.itemMap = new LinkedHashMap<>();
        this.selectionChangedlistener = new RadioGroup.OnCheckedChangeListener() { // from class: im.uwrkaxlmjj.ui.hviews.SegmenteView.1
            @Override // android.widget.RadioGroup.OnCheckedChangeListener
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                View viewById = group.findViewById(checkedId);
                if (viewById.isPressed() && SegmenteView.this.mListener != null) {
                    SegmenteView.this.mListener.onItemSelected(checkedId);
                }
            }
        };
        init(context);
        TypedArray attributes = context.getTheme().obtainStyledAttributes(attrs, R.styleable.MultipleSelectionButton, 0, 0);
        try {
            this.selectedColor = attributes.getColor(4, this.selectedColor);
            this.selectedTextColor = attributes.getColor(5, this.selectedTextColor);
            this.unselectedColor = attributes.getColor(7, this.unselectedColor);
            this.unselectedTextColor = attributes.getColor(8, this.selectedColor);
            this.textColorStateList = new ColorStateList(new int[][]{new int[]{-16842912}, new int[]{android.R.attr.state_checked}}, new int[]{this.unselectedTextColor, this.selectedTextColor});
            this.defaultSelection = attributes.getInt(0, this.defaultSelection);
            this.equalWidth = attributes.getBoolean(1, this.equalWidth);
            this.stretch = attributes.getBoolean(6, this.stretch);
            this.identifier = attributes.getString(2);
            CharSequence[] itemArray = attributes.getTextArray(3);
            CharSequence[] valueArray = attributes.getTextArray(9);
            itemArray = isInEditMode() ? new CharSequence[]{"YES", "NO", "MAYBE", "DON'T KNOW"} : itemArray;
            if (itemArray != null && valueArray != null && itemArray.length != valueArray.length) {
                throw new Exception("Item labels and value arrays must be the same size");
            }
            if (itemArray != null) {
                if (valueArray != null) {
                    for (int i = 0; i < itemArray.length; i++) {
                        this.itemMap.put(itemArray[i].toString(), valueArray[i].toString());
                    }
                } else {
                    for (CharSequence item : itemArray) {
                        this.itemMap.put(item.toString(), item.toString());
                    }
                }
            }
            attributes.recycle();
            update();
        } catch (Throwable th) {
            attributes.recycle();
            throw th;
        }
    }

    private void init(Context context) {
        this.mCtx = context;
        this.mSdk = Build.VERSION.SDK_INT;
        setPadding(10, 10, 10, 10);
    }

    private void update() {
        removeAllViews();
        float f = 1.0f;
        int twoDP = (int) TypedValue.applyDimension(1, 1.0f, getResources().getDisplayMetrics());
        setOrientation(0);
        float textWidth = 0.0f;
        this.options = new ArrayList<>();
        int i = 0;
        for (Map.Entry<String, String> item : this.itemMap.entrySet()) {
            RadioButton rb = new RadioButton(this.mCtx);
            rb.setTextColor(this.textColorStateList);
            RadioGroup.LayoutParams params = new RadioGroup.LayoutParams(-2, -1);
            if (this.stretch) {
                params.weight = f;
            }
            if (i > 0) {
                params.setMargins(-twoDP, 0, 0, 0);
            }
            rb.setLayoutParams(params);
            rb.setButtonDrawable(new StateListDrawable());
            if (i != 0) {
                if (i == this.itemMap.size() - 1) {
                    GradientDrawable rightUnselected = (GradientDrawable) this.mCtx.getResources().getDrawable(mpEIGo.juqQQs.esbSDO.R.drawable.right_option).mutate();
                    rightUnselected.setStroke(twoDP, this.selectedColor);
                    rightUnselected.setColor(this.unselectedColor);
                    GradientDrawable rightSelected = (GradientDrawable) this.mCtx.getResources().getDrawable(mpEIGo.juqQQs.esbSDO.R.drawable.right_option_selected).mutate();
                    rightSelected.setColor(this.selectedColor);
                    rightSelected.setStroke(twoDP, this.selectedColor);
                    StateListDrawable rightStateListDrawable = new StateListDrawable();
                    rightStateListDrawable.addState(new int[]{-16842912}, rightUnselected);
                    rightStateListDrawable.addState(new int[]{android.R.attr.state_checked}, rightSelected);
                    if (this.mSdk < 16) {
                        rb.setBackgroundDrawable(rightStateListDrawable);
                    } else {
                        rb.setBackground(rightStateListDrawable);
                    }
                } else {
                    GradientDrawable middleUnselected = (GradientDrawable) this.mCtx.getResources().getDrawable(mpEIGo.juqQQs.esbSDO.R.drawable.middle_option).mutate();
                    middleUnselected.setStroke(twoDP, this.selectedColor);
                    middleUnselected.setDither(true);
                    middleUnselected.setColor(this.unselectedColor);
                    GradientDrawable middleSelected = (GradientDrawable) this.mCtx.getResources().getDrawable(mpEIGo.juqQQs.esbSDO.R.drawable.middle_option_selected).mutate();
                    middleSelected.setColor(this.selectedColor);
                    middleSelected.setStroke(twoDP, this.selectedColor);
                    StateListDrawable middleStateListDrawable = new StateListDrawable();
                    middleStateListDrawable.addState(new int[]{-16842912}, middleUnselected);
                    middleStateListDrawable.addState(new int[]{android.R.attr.state_checked}, middleSelected);
                    if (this.mSdk < 16) {
                        rb.setBackgroundDrawable(middleStateListDrawable);
                    } else {
                        rb.setBackground(middleStateListDrawable);
                    }
                }
            } else {
                GradientDrawable leftUnselected = (GradientDrawable) this.mCtx.getResources().getDrawable(mpEIGo.juqQQs.esbSDO.R.drawable.left_option).mutate();
                leftUnselected.setStroke(twoDP, this.selectedColor);
                leftUnselected.setColor(this.unselectedColor);
                GradientDrawable leftSelected = (GradientDrawable) this.mCtx.getResources().getDrawable(mpEIGo.juqQQs.esbSDO.R.drawable.left_option_selected).mutate();
                leftSelected.setColor(this.selectedColor);
                leftSelected.setStroke(twoDP, this.selectedColor);
                StateListDrawable leftStateListDrawable = new StateListDrawable();
                leftStateListDrawable.addState(new int[]{-16842912}, leftUnselected);
                leftStateListDrawable.addState(new int[]{android.R.attr.state_checked}, leftSelected);
                if (this.mSdk < 16) {
                    rb.setBackgroundDrawable(leftStateListDrawable);
                } else {
                    rb.setBackground(leftStateListDrawable);
                }
            }
            rb.setLayoutParams(params);
            rb.setMinWidth(twoDP * 10);
            rb.setGravity(17);
            rb.setTypeface(null, 1);
            rb.setText(item.getKey());
            textWidth = Math.max(rb.getPaint().measureText(item.getKey()), textWidth);
            this.options.add(rb);
            i++;
            f = 1.0f;
        }
        for (RadioButton option : this.options) {
            if (this.equalWidth) {
                option.setWidth((int) ((twoDP * 20) + textWidth));
            }
            addView(option);
        }
        setOnCheckedChangeListener(this.selectionChangedlistener);
        int i2 = this.defaultSelection;
        if (i2 > -1) {
            check(((RadioButton) getChildAt(i2)).getId());
        }
    }

    public String[] getCheckedWithIdentifier() {
        return new String[]{this.identifier, this.itemMap.get(((RadioButton) findViewById(getCheckedRadioButtonId())).getText().toString())};
    }

    public String getChecked() {
        return this.itemMap.get(((RadioButton) findViewById(getCheckedRadioButtonId())).getText().toString());
    }

    public void setItems(String[] itemArray, String[] valueArray) throws Exception {
        this.itemMap.clear();
        if (itemArray != null && valueArray != null && itemArray.length != valueArray.length) {
            throw new Exception("Item labels and value arrays must be the same size");
        }
        if (itemArray != null) {
            if (valueArray != null) {
                for (int i = 0; i < itemArray.length; i++) {
                    this.itemMap.put(itemArray[i].toString(), valueArray[i].toString());
                }
            } else {
                for (String str : itemArray) {
                    this.itemMap.put(str.toString(), str.toString());
                }
            }
        }
        update();
    }

    public void setItems(String[] items, String[] values, int defaultSelection) throws Exception {
        if (defaultSelection > items.length - 1) {
            throw new Exception("Default selection cannot be greater than the number of items");
        }
        this.defaultSelection = defaultSelection;
        setItems(items, values);
    }

    public void setDefaultSelection(int defaultSelection) throws Exception {
        if (defaultSelection > this.itemMap.size() - 1) {
            throw new Exception("Default selection cannot be greater than the number of items");
        }
        this.defaultSelection = defaultSelection;
        update();
    }

    public void setColors(int primaryColor, int secondaryColor) {
        this.selectedColor = primaryColor;
        this.selectedTextColor = secondaryColor;
        this.unselectedColor = secondaryColor;
        this.unselectedTextColor = primaryColor;
        this.textColorStateList = new ColorStateList(new int[][]{new int[]{-16842912}, new int[]{android.R.attr.state_checked}}, new int[]{this.unselectedTextColor, this.selectedTextColor});
        update();
    }

    public void setColors(int selectedColor, int selectedTextColor, int unselectedColor, int unselectedTextColor) {
        this.selectedColor = selectedColor;
        this.selectedTextColor = selectedTextColor;
        this.unselectedColor = unselectedColor;
        this.unselectedTextColor = unselectedTextColor;
        this.textColorStateList = new ColorStateList(new int[][]{new int[]{-16842912}, new int[]{android.R.attr.state_checked}}, new int[]{unselectedTextColor, selectedTextColor});
        update();
    }

    public void setByValue(String value) {
        String buttonText = "";
        if (this.itemMap.containsValue(value)) {
            for (String entry : this.itemMap.keySet()) {
                if (this.itemMap.get(entry).equalsIgnoreCase(value)) {
                    buttonText = entry;
                }
            }
        }
        for (RadioButton option : this.options) {
            if (option.getText().toString().equalsIgnoreCase(buttonText)) {
                check(option.getId());
            }
        }
    }

    public void setOnSelectionChangedListener(OnSelectionChangedListener listener) {
        this.mListener = listener;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public void setEqualWidth(boolean equalWidth) {
        this.equalWidth = equalWidth;
        update();
    }

    public void setStretch(boolean stretch) {
        this.stretch = stretch;
        update();
    }
}
