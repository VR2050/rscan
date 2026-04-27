package im.uwrkaxlmjj.ui.bottom;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.R;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import java.util.Locale;

/* JADX INFO: loaded from: classes5.dex */
public class BottomBarItem extends LinearLayout {
    private Context context;
    private int iconHeight;
    private String iconUrl;
    private int iconUrlErrorResId;
    private int iconUrlPlaceHolderResId;
    private int iconWidth;
    private int itemPadding;
    private ImageView mImageView;
    private TextView mTextView;
    private TextView mTvMsg;
    private TextView mTvNotify;
    private TextView mTvUnread;
    private int marginTop;
    private Drawable msgTextBg;
    private int msgTextColor;
    private int msgTextSize;
    private Drawable normalIcon;
    private Drawable notifyPointBg;
    private boolean openTouchBg;
    private Drawable selectedIcon;
    private String title;
    private String titleKey;
    private int titleNormalColor;
    private int titleSelectedColor;
    private int titleTextSize;
    private Drawable touchDrawable;
    private int unreadNumThreshold;
    private Drawable unreadTextBg;
    private int unreadTextColor;
    private int unreadTextSize;

    public BottomBarItem(Context context) {
        this(context, null);
    }

    public BottomBarItem(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public BottomBarItem(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.titleTextSize = 12;
        this.marginTop = 0;
        this.openTouchBg = false;
        this.unreadTextSize = 10;
        this.unreadNumThreshold = 99;
        this.msgTextSize = 6;
        this.context = context;
        TypedArray ta = context.obtainStyledAttributes(attrs, R.styleable.BottomBarItem);
        initAttrs(ta);
        ta.recycle();
        checkValues();
        init();
    }

    private void initAttrs(TypedArray ta) {
        this.normalIcon = ta.getDrawable(1);
        this.selectedIcon = ta.getDrawable(2);
        this.titleKey = ta.getString(6);
        this.titleTextSize = ta.getDimensionPixelSize(7, UIUtils.sp2px(this.context, this.titleTextSize));
        this.titleNormalColor = ta.getColor(13, UIUtils.getColor(this.context, mpEIGo.juqQQs.esbSDO.R.color.bbl_999999));
        this.titleSelectedColor = ta.getColor(14, UIUtils.getColor(this.context, mpEIGo.juqQQs.esbSDO.R.color.bbl_ff0000));
        this.titleNormalColor = Theme.getColor(Theme.key_bottomBarNormalColor);
        this.titleSelectedColor = Theme.getColor(Theme.key_bottomBarSelectedColor);
        this.marginTop = ta.getDimensionPixelSize(4, UIUtils.dip2Px(this.context, this.marginTop));
        this.openTouchBg = ta.getBoolean(12, this.openTouchBg);
        this.touchDrawable = ta.getDrawable(15);
        this.iconWidth = ta.getDimensionPixelSize(3, 0);
        this.iconHeight = ta.getDimensionPixelSize(0, 0);
        this.itemPadding = ta.getDimensionPixelSize(5, 0);
        this.unreadTextSize = ta.getDimensionPixelSize(18, UIUtils.sp2px(this.context, this.unreadTextSize));
        this.unreadTextColor = ta.getColor(17, UIUtils.getColor(this.context, mpEIGo.juqQQs.esbSDO.R.color.white));
        this.unreadTextBg = ta.getDrawable(16);
        this.msgTextSize = ta.getDimensionPixelSize(10, UIUtils.sp2px(this.context, this.msgTextSize));
        this.msgTextColor = ta.getColor(9, UIUtils.getColor(this.context, mpEIGo.juqQQs.esbSDO.R.color.white));
        this.msgTextBg = ta.getDrawable(8);
        this.notifyPointBg = ta.getDrawable(11);
        this.unreadNumThreshold = ta.getInteger(19, this.unreadNumThreshold);
    }

    private void checkValues() {
        if (this.openTouchBg && this.touchDrawable == null) {
            throw new IllegalStateException("Touch effect is turned on, but touchDrawable is not specified");
        }
        if (this.unreadTextBg == null) {
            this.unreadTextBg = getResources().getDrawable(mpEIGo.juqQQs.esbSDO.R.drawable.shape_unread);
        }
        if (this.msgTextBg == null) {
            this.msgTextBg = getResources().getDrawable(mpEIGo.juqQQs.esbSDO.R.drawable.shape_msg);
        }
        if (this.notifyPointBg == null) {
            this.notifyPointBg = getResources().getDrawable(mpEIGo.juqQQs.esbSDO.R.drawable.shape_notify_point);
        }
    }

    private void init() {
        String str;
        setOrientation(1);
        setGravity(17);
        View view = initView();
        Drawable drawable = this.normalIcon;
        if (drawable != null) {
            this.mImageView.setImageDrawable(drawable);
        }
        if (this.iconWidth != 0 && this.iconHeight != 0) {
            RelativeLayout.LayoutParams imageLayoutParams = (RelativeLayout.LayoutParams) this.mImageView.getLayoutParams();
            imageLayoutParams.width = this.iconWidth;
            imageLayoutParams.height = this.iconHeight;
            this.mImageView.setLayoutParams(imageLayoutParams);
        }
        this.mTextView.setTextSize(0, this.titleTextSize);
        this.mTvUnread.setTextSize(0, this.unreadTextSize);
        this.mTvUnread.setTextColor(this.unreadTextColor);
        this.mTvUnread.setBackground(this.unreadTextBg);
        this.mTvMsg.setTextSize(0, this.msgTextSize);
        this.mTvMsg.setTextColor(this.msgTextColor);
        this.mTvMsg.setBackground(this.msgTextBg);
        this.mTvNotify.setBackground(this.notifyPointBg);
        this.mTextView.setTextColor(this.titleNormalColor);
        if (this.title == null && (str = this.titleKey) != null) {
            this.title = LocaleController.getServerString(str);
        }
        setTitle(this.title);
        LinearLayout.LayoutParams textLayoutParams = (LinearLayout.LayoutParams) this.mTextView.getLayoutParams();
        textLayoutParams.topMargin = this.marginTop;
        this.mTextView.setLayoutParams(textLayoutParams);
        if (this.openTouchBg) {
            setBackground(this.touchDrawable);
        }
        addView(view);
    }

    public void setTitle(String title) {
        if (TextUtils.isEmpty(title)) {
            if (this.mTextView.getVisibility() != 8) {
                this.mTextView.setVisibility(8);
            }
        } else {
            if (this.mTextView.getVisibility() != 0) {
                this.mTextView.setVisibility(0);
            }
            this.mTextView.setText(title);
        }
    }

    private View initView() {
        View view = View.inflate(this.context, mpEIGo.juqQQs.esbSDO.R.layout.item_bottom_bar, null);
        int i = this.itemPadding;
        if (i != 0) {
            view.setPadding(i, i, i, i);
        }
        this.mImageView = (ImageView) view.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.iv_icon);
        this.mTvUnread = (TextView) view.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_unred_num);
        this.mTvMsg = (TextView) view.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_msg);
        this.mTvNotify = (TextView) view.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_point);
        this.mTextView = (TextView) view.findViewById(mpEIGo.juqQQs.esbSDO.R.attr.tv_text);
        return view;
    }

    public ImageView getImageView() {
        return this.mImageView;
    }

    public TextView getTextView() {
        return this.mTextView;
    }

    public void setNormalIcon(Drawable normalIcon) {
        this.normalIcon = normalIcon;
        refreshTab();
    }

    public void setNormalIcon(int resId) {
        setNormalIcon(UIUtils.getDrawable(this.context, resId));
    }

    public void setSelectedIcon(Drawable selectedIcon) {
        this.selectedIcon = selectedIcon;
        refreshTab();
    }

    public void setSelectedIcon(int resId) {
        setSelectedIcon(UIUtils.getDrawable(this.context, resId));
    }

    public void setIconUrl(String url) {
        this.iconUrl = url;
        refreshTab();
    }

    public void refreshTab(boolean isSelected) {
        setSelected(isSelected);
        refreshTab();
    }

    public void refreshTab() {
        if ((isSelected() && this.selectedIcon != null) || (!isSelected() && this.normalIcon != null)) {
            this.mImageView.setImageDrawable(isSelected() ? this.selectedIcon : this.normalIcon);
        }
        this.mTextView.setTextColor(isSelected() ? this.titleSelectedColor : this.titleNormalColor);
    }

    private void setTvVisible(TextView tv) {
        this.mTvUnread.setVisibility(8);
        this.mTvMsg.setVisibility(8);
        this.mTvNotify.setVisibility(8);
        tv.setVisibility(0);
    }

    public int getUnreadNumThreshold() {
        return this.unreadNumThreshold;
    }

    public void setUnreadNumThreshold(int unreadNumThreshold) {
        this.unreadNumThreshold = unreadNumThreshold;
    }

    public void setUnreadNum(int unreadNum) {
        setTvVisible(this.mTvUnread);
        if (unreadNum <= 0) {
            this.mTvUnread.setVisibility(8);
        } else if (unreadNum <= this.unreadNumThreshold) {
            this.mTvUnread.setText(String.valueOf(unreadNum));
        } else {
            this.mTvUnread.setText(String.format(Locale.CHINA, "%d+", Integer.valueOf(this.unreadNumThreshold)));
        }
    }

    public void setMsg(String msg) {
        setTvVisible(this.mTvMsg);
        this.mTvMsg.setText(msg);
    }

    public void hideMsg() {
        this.mTvMsg.setVisibility(8);
    }

    public void showNotify() {
        setTvVisible(this.mTvNotify);
    }

    public void hideNotify() {
        this.mTvNotify.setVisibility(8);
    }

    public BottomBarItem create(Builder builder) {
        this.context = builder.context;
        this.normalIcon = builder.normalIcon;
        this.selectedIcon = builder.selectedIcon;
        this.iconUrl = builder.iconUrl;
        this.title = builder.title;
        this.titleTextSize = builder.titleTextSize;
        this.titleNormalColor = builder.titleNormalColor;
        this.titleSelectedColor = builder.titleSelectedColor;
        this.marginTop = builder.marginTop;
        this.openTouchBg = builder.openTouchBg;
        this.touchDrawable = builder.touchDrawable;
        this.iconWidth = builder.iconWidth;
        this.iconHeight = builder.iconHeight;
        this.itemPadding = builder.itemPadding;
        this.unreadTextSize = builder.unreadTextSize;
        this.unreadTextColor = builder.unreadTextColor;
        this.unreadTextBg = builder.unreadTextBg;
        this.unreadNumThreshold = builder.unreadNumThreshold;
        this.msgTextSize = builder.msgTextSize;
        this.msgTextColor = builder.msgTextColor;
        this.msgTextBg = builder.msgTextBg;
        this.notifyPointBg = builder.notifyPointBg;
        checkValues();
        init();
        return this;
    }

    public static final class Builder {
        private Context context;
        private int iconHeight;
        private String iconUrl;
        private int iconUrlErrorResId;
        private int iconUrlPlaceHolderResId;
        private int iconWidth;
        private int itemPadding;
        private int marginTop;
        private Drawable msgTextBg;
        private int msgTextSize;
        private Drawable normalIcon;
        private Drawable notifyPointBg;
        private boolean openTouchBg;
        private Drawable selectedIcon;
        private String title;
        private int titleTextSize;
        private Drawable touchDrawable;
        private Drawable unreadTextBg;
        private int unreadTextSize;
        private int titleNormalColor = getColor(mpEIGo.juqQQs.esbSDO.R.color.color_btm_text_normal);
        private int titleSelectedColor = getColor(mpEIGo.juqQQs.esbSDO.R.color.color_btm_text_selected);
        private int unreadTextColor = getColor(mpEIGo.juqQQs.esbSDO.R.color.white);
        private int unreadNumThreshold = 99;
        private int msgTextColor = getColor(mpEIGo.juqQQs.esbSDO.R.color.white);

        public Builder(Context context) {
            this.context = context;
            this.titleTextSize = UIUtils.sp2px(context, 10.0f);
            this.iconWidth = UIUtils.dip2Px(context, 22);
            this.iconHeight = UIUtils.dip2Px(context, 22);
            this.marginTop = UIUtils.dip2Px(context, 5);
            this.itemPadding = UIUtils.dip2Px(context, 2);
            this.unreadTextSize = UIUtils.sp2px(context, 10.0f);
            this.msgTextSize = UIUtils.sp2px(context, 6.0f);
        }

        public Builder normalIcon(Drawable normalIcon) {
            this.normalIcon = normalIcon;
            return this;
        }

        public Builder selectedIcon(Drawable selectedIcon) {
            this.selectedIcon = selectedIcon;
            return this;
        }

        public Builder title(int titleId) {
            this.title = this.context.getString(titleId);
            return this;
        }

        public Builder title(String title) {
            this.title = title;
            return this;
        }

        public Builder titleTextSize(int titleTextSize) {
            this.titleTextSize = UIUtils.sp2px(this.context, titleTextSize);
            return this;
        }

        public Builder titleNormalColor(int titleNormalColor) {
            this.titleNormalColor = getColor(titleNormalColor);
            return this;
        }

        public Builder titleSelectedColor(int titleSelectedColor) {
            this.titleSelectedColor = getColor(titleSelectedColor);
            return this;
        }

        public Builder marginTop(int marginTop) {
            this.marginTop = marginTop;
            return this;
        }

        public Builder openTouchBg(boolean openTouchBg) {
            this.openTouchBg = openTouchBg;
            return this;
        }

        public Builder touchDrawable(Drawable touchDrawable) {
            this.touchDrawable = touchDrawable;
            return this;
        }

        public Builder iconWidth(int iconWidth) {
            this.iconWidth = iconWidth;
            return this;
        }

        public Builder iconHeight(int iconHeight) {
            this.iconHeight = iconHeight;
            return this;
        }

        public Builder itemPadding(int itemPadding) {
            this.itemPadding = itemPadding;
            return this;
        }

        public Builder unreadTextSize(int unreadTextSize) {
            this.unreadTextSize = UIUtils.sp2px(this.context, unreadTextSize);
            return this;
        }

        public Builder unreadNumThreshold(int unreadNumThreshold) {
            this.unreadNumThreshold = unreadNumThreshold;
            return this;
        }

        public Builder msgTextSize(int msgTextSize) {
            this.msgTextSize = UIUtils.sp2px(this.context, msgTextSize);
            return this;
        }

        public Builder unreadTextBg(Drawable unreadTextBg) {
            this.unreadTextBg = unreadTextBg;
            return this;
        }

        public Builder unreadTextColor(int unreadTextColor) {
            this.unreadTextColor = getColor(unreadTextColor);
            return this;
        }

        public Builder msgTextColor(int msgTextColor) {
            this.msgTextColor = getColor(msgTextColor);
            return this;
        }

        public Builder msgTextBg(Drawable msgTextBg) {
            this.msgTextBg = msgTextBg;
            return this;
        }

        public Builder notifyPointBg(Drawable notifyPointBg) {
            this.notifyPointBg = notifyPointBg;
            return this;
        }

        public BottomBarItem create(Drawable normalIcon, Drawable selectedIcon, String text) {
            this.normalIcon = normalIcon;
            this.selectedIcon = selectedIcon;
            this.title = text;
            BottomBarItem bottomBarItem = new BottomBarItem(this.context);
            return bottomBarItem.create(this);
        }

        public BottomBarItem create(int normalIconId, int selectedIconId, String text) {
            return create(UIUtils.getDrawable(this.context, normalIconId), UIUtils.getDrawable(this.context, selectedIconId), text);
        }

        public BottomBarItem create(String iconUrl, int iconUrlErrorResId, int iconUrlPlaceHolderResId, String text) {
            this.iconUrl = iconUrl;
            this.title = text;
            BottomBarItem bottomBarItem = new BottomBarItem(this.context);
            return bottomBarItem.create(this);
        }

        private int getColor(int colorId) {
            return this.context.getResources().getColor(colorId);
        }
    }
}
