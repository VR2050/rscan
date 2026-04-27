package im.uwrkaxlmjj.ui.cell;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.R;
import im.uwrkaxlmjj.ui.actionbar.Theme;

/* JADX INFO: loaded from: classes5.dex */
public class SettingsItem extends FrameLayout {
    private String desc;
    private View divLine;
    private boolean divider;
    private Drawable leftDrawable;
    private ImageView leftImageView;
    private Context mContext;
    private int paddingLeft;
    private Drawable rightDrawable;
    private ImageView rightImageView;
    private String subTitle;
    private String title;
    private TextView tvItemDescText;
    private TextView tvItemSubTitle;
    private TextView tvItemTitle;

    public SettingsItem(Context context) {
        this(context, null);
    }

    public SettingsItem(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public SettingsItem(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mContext = context;
        initAttrs(attrs);
        init();
    }

    private void initAttrs(AttributeSet attrs) {
        TypedArray ta = this.mContext.obtainStyledAttributes(attrs, R.styleable.SettingsItem);
        this.leftDrawable = ta.getDrawable(3);
        this.rightDrawable = ta.getDrawable(4);
        this.title = ta.getString(6);
        this.subTitle = ta.getString(5);
        this.desc = ta.getString(0);
        this.divider = ta.getBoolean(2, true);
        this.paddingLeft = ta.getDimensionPixelSize(1, 0);
        ta.recycle();
    }

    private View initInflate() {
        View view = View.inflate(this.mContext, mpEIGo.juqQQs.esbSDO.R.layout.item_settings_layout, null);
        this.leftImageView = (ImageView) view.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.ivLeftIcon);
        this.rightImageView = (ImageView) view.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.ivRightIcon);
        this.tvItemTitle = (TextView) view.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tvItemTitle);
        this.tvItemSubTitle = (TextView) view.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tvItemSubTitle);
        this.tvItemDescText = (TextView) view.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tvItemDescText);
        this.tvItemDescText = (TextView) view.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tvItemDescText);
        this.divLine = view.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.divLine);
        return view;
    }

    private void init() {
        View view = initInflate();
        addView(view);
        setBackground(Theme.createSimpleSelectorRoundRectDrawable(AndroidUtilities.dp(24.0f), Color.parseColor("#FF268CFF"), Color.parseColor("#FF1E69BD")));
        boolean flag = this.leftDrawable != null;
        if (flag) {
            this.leftImageView.setImageDrawable(this.leftDrawable);
        }
        this.leftImageView.setVisibility(flag ? 0 : 8);
        boolean flag2 = this.title != null;
        if (flag2) {
            this.tvItemTitle.setText(this.title);
        }
        this.tvItemTitle.setVisibility(flag2 ? 0 : 8);
        boolean flag3 = this.subTitle != null;
        if (flag3) {
            this.tvItemSubTitle.setText(this.subTitle);
        }
        this.tvItemSubTitle.setVisibility(flag3 ? 0 : 8);
        String str = this.subTitle;
        if (str != null) {
            this.tvItemSubTitle.setText(str);
        }
        String str2 = this.desc;
        if (str2 != null) {
            this.tvItemDescText.setText(str2);
        }
        boolean flag4 = this.desc != null;
        if (flag4) {
            this.tvItemDescText.setText(this.desc);
        }
        this.tvItemDescText.setVisibility(flag4 ? 0 : 8);
        boolean flag5 = this.rightDrawable != null;
        if (flag5) {
            this.rightImageView.setImageDrawable(this.rightDrawable);
        }
        this.rightImageView.setVisibility(flag5 ? 0 : 8);
        this.divLine.setVisibility(this.divider ? 0 : 8);
        if (this.paddingLeft != 0) {
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.divLine.getLayoutParams();
            layoutParams.setMargins(this.paddingLeft, 0, 0, 0);
            this.divLine.setLayoutParams(layoutParams);
        }
    }

    private void setData(int ltResId, String title, String subTitle, boolean arrow, boolean divider) {
        setData(ltResId, title, subTitle, null, arrow ? mpEIGo.juqQQs.esbSDO.R.id.icon_arrow_right : 0, divider);
    }

    private void setData(int ltResId, String title, boolean arrow, boolean divier) {
        setData(ltResId, title, this.subTitle, null, arrow ? mpEIGo.juqQQs.esbSDO.R.id.icon_arrow_right : 0, this.divider);
    }

    private void setData(int ltResId, String title, String subTitle, String desc, int gtResId, boolean divider) {
        boolean flag = ltResId > 0;
        this.leftImageView.setVisibility(flag ? 0 : 8);
        if (flag) {
            this.leftImageView.setImageResource(ltResId);
        }
        this.tvItemTitle.setVisibility(0);
        this.tvItemTitle.setText(title);
        boolean flag2 = subTitle != null;
        this.tvItemSubTitle.setVisibility(flag2 ? 0 : 8);
        if (flag2) {
            this.tvItemSubTitle.setText(subTitle);
        }
        boolean flag3 = desc != null;
        this.tvItemDescText.setVisibility(flag3 ? 0 : 8);
        if (flag3) {
            this.tvItemDescText.setText(desc);
        }
        boolean flag4 = gtResId > 0;
        this.rightImageView.setVisibility(flag4 ? 0 : 8);
        if (flag4) {
            this.rightImageView.setImageResource(ltResId);
        }
        this.divLine.setVisibility(divider ? 0 : 8);
        if (divider && this.paddingLeft > 0) {
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.divLine.getLayoutParams();
            layoutParams.setMargins(this.paddingLeft, 0, 0, 0);
            this.divLine.setLayoutParams(layoutParams);
        }
        invalidate();
    }
}
