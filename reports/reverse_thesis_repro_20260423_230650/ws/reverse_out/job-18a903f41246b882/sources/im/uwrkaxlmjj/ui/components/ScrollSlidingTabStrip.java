package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.os.SystemClock;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ScrollSlidingTabStrip extends HorizontalScrollView {
    private boolean animateFromPosition;
    private int currentPosition;
    private LinearLayout.LayoutParams defaultExpandLayoutParams;
    private LinearLayout.LayoutParams defaultTabLayoutParams;
    private ScrollSlidingTabStripDelegate delegate;
    private int dividerPadding;
    private int indicatorColor;
    private int indicatorHeight;
    private long lastAnimationTime;
    private int lastScrollX;
    private float positionAnimationProgress;
    private Paint rectPaint;
    private int scrollOffset;
    private boolean shouldExpand;
    private float startAnimationPosition;
    private int tabCount;
    private int tabPadding;
    private LinearLayout tabsContainer;
    private int underlineColor;
    private int underlineHeight;

    public interface ScrollSlidingTabStripDelegate {
        void onPageSelected(int i);
    }

    public ScrollSlidingTabStrip(Context context) {
        super(context);
        this.indicatorColor = -10066330;
        this.underlineColor = 436207616;
        this.scrollOffset = AndroidUtilities.dp(52.0f);
        this.underlineHeight = AndroidUtilities.dp(2.0f);
        this.dividerPadding = AndroidUtilities.dp(12.0f);
        this.tabPadding = AndroidUtilities.dp(24.0f);
        this.lastScrollX = 0;
        setFillViewport(true);
        setWillNotDraw(false);
        setHorizontalScrollBarEnabled(false);
        LinearLayout linearLayout = new LinearLayout(context);
        this.tabsContainer = linearLayout;
        linearLayout.setOrientation(0);
        this.tabsContainer.setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
        addView(this.tabsContainer);
        Paint paint = new Paint();
        this.rectPaint = paint;
        paint.setAntiAlias(true);
        this.rectPaint.setStyle(Paint.Style.FILL);
        this.defaultTabLayoutParams = new LinearLayout.LayoutParams(AndroidUtilities.dp(52.0f), -1);
        this.defaultExpandLayoutParams = new LinearLayout.LayoutParams(0, -1, 1.0f);
    }

    public void setDelegate(ScrollSlidingTabStripDelegate scrollSlidingTabStripDelegate) {
        this.delegate = scrollSlidingTabStripDelegate;
    }

    public void removeTabs() {
        this.tabsContainer.removeAllViews();
        this.tabCount = 0;
        this.currentPosition = 0;
        this.animateFromPosition = false;
    }

    public void selectTab(int num) {
        if (num < 0 || num >= this.tabCount) {
            return;
        }
        View tab = this.tabsContainer.getChildAt(num);
        tab.performClick();
    }

    public TextView addIconTabWithCounter(Drawable drawable) {
        final int position = this.tabCount;
        this.tabCount = position + 1;
        FrameLayout tab = new FrameLayout(getContext());
        tab.setFocusable(true);
        this.tabsContainer.addView(tab);
        ImageView imageView = new ImageView(getContext());
        imageView.setImageDrawable(drawable);
        imageView.setScaleType(ImageView.ScaleType.CENTER);
        tab.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ScrollSlidingTabStrip$mqPrtn5ttpFalC_5T6YqWlt5wjw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$addIconTabWithCounter$0$ScrollSlidingTabStrip(position, view);
            }
        });
        tab.addView(imageView, LayoutHelper.createFrame(-1, -1.0f));
        tab.setSelected(position == this.currentPosition);
        TextView textView = new TextView(getContext());
        textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        textView.setTextSize(1, 12.0f);
        textView.setTextColor(Theme.getColor(Theme.key_chat_emojiPanelBadgeText));
        textView.setGravity(17);
        textView.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(9.0f), Theme.getColor(Theme.key_chat_emojiPanelBadgeBackground)));
        textView.setMinWidth(AndroidUtilities.dp(18.0f));
        textView.setPadding(AndroidUtilities.dp(5.0f), 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(1.0f));
        tab.addView(textView, LayoutHelper.createFrame(-2.0f, 18.0f, 51, 26.0f, 6.0f, 0.0f, 0.0f));
        return textView;
    }

    public /* synthetic */ void lambda$addIconTabWithCounter$0$ScrollSlidingTabStrip(int position, View v) {
        this.delegate.onPageSelected(position);
    }

    public ImageView addIconTab(Drawable drawable) {
        final int position = this.tabCount;
        this.tabCount = position + 1;
        ImageView tab = new ImageView(getContext());
        tab.setFocusable(true);
        tab.setImageDrawable(drawable);
        tab.setScaleType(ImageView.ScaleType.CENTER);
        tab.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ScrollSlidingTabStrip$nY-6sbIIIZTf5PnKTbxeXR3RxKI
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$addIconTab$1$ScrollSlidingTabStrip(position, view);
            }
        });
        this.tabsContainer.addView(tab);
        tab.setSelected(position == this.currentPosition);
        return tab;
    }

    public /* synthetic */ void lambda$addIconTab$1$ScrollSlidingTabStrip(int position, View v) {
        this.delegate.onPageSelected(position);
    }

    public void addStickerTab(TLRPC.Chat chat) {
        final int position = this.tabCount;
        this.tabCount = position + 1;
        FrameLayout frameLayout = new FrameLayout(getContext());
        frameLayout.setFocusable(true);
        frameLayout.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ScrollSlidingTabStrip$7awS3BNK6R1myqOABc1Bs0dVyb4
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$addStickerTab$2$ScrollSlidingTabStrip(position, view);
            }
        });
        this.tabsContainer.addView(frameLayout);
        frameLayout.setSelected(position == this.currentPosition);
        BackupImageView imageView = new BackupImageView(getContext());
        imageView.setLayerNum(1);
        imageView.setRoundRadius(AndroidUtilities.dp(15.0f));
        AvatarDrawable avatarDrawable = new AvatarDrawable();
        avatarDrawable.setTextSize(AndroidUtilities.dp(14.0f));
        avatarDrawable.setInfo(chat);
        imageView.setImage(ImageLocation.getForChat(chat, false), "50_50", avatarDrawable, chat);
        imageView.setAspectFit(true);
        frameLayout.addView(imageView, LayoutHelper.createFrame(30, 30, 17));
    }

    public /* synthetic */ void lambda$addStickerTab$2$ScrollSlidingTabStrip(int position, View v) {
        this.delegate.onPageSelected(position);
    }

    public View addStickerTab(TLObject thumb, TLRPC.Document sticker, Object parentObject) {
        final int position = this.tabCount;
        this.tabCount = position + 1;
        FrameLayout tab = new FrameLayout(getContext());
        tab.setTag(thumb);
        tab.setTag(R.attr.parent_tag, parentObject);
        tab.setTag(R.attr.object_tag, sticker);
        tab.setFocusable(true);
        tab.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ScrollSlidingTabStrip$NSn3VdNl39kavawgZxhfXV4xcok
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$addStickerTab$3$ScrollSlidingTabStrip(position, view);
            }
        });
        this.tabsContainer.addView(tab);
        tab.setSelected(position == this.currentPosition);
        BackupImageView imageView = new BackupImageView(getContext());
        imageView.setLayerNum(1);
        imageView.setAspectFit(true);
        tab.addView(imageView, LayoutHelper.createFrame(30, 30, 17));
        return tab;
    }

    public /* synthetic */ void lambda$addStickerTab$3$ScrollSlidingTabStrip(int position, View v) {
        this.delegate.onPageSelected(position);
    }

    public void updateTabStyles() {
        for (int i = 0; i < this.tabCount; i++) {
            View v = this.tabsContainer.getChildAt(i);
            if (this.shouldExpand) {
                v.setLayoutParams(this.defaultExpandLayoutParams);
            } else {
                v.setLayoutParams(this.defaultTabLayoutParams);
            }
        }
    }

    private void scrollToChild(int position) {
        if (this.tabCount == 0 || this.tabsContainer.getChildAt(position) == null) {
            return;
        }
        int newScrollX = this.tabsContainer.getChildAt(position).getLeft();
        if (position > 0) {
            newScrollX -= this.scrollOffset;
        }
        int currentScrollX = getScrollX();
        if (newScrollX != this.lastScrollX) {
            if (newScrollX < currentScrollX) {
                this.lastScrollX = newScrollX;
                smoothScrollTo(newScrollX, 0);
            } else if (this.scrollOffset + newScrollX > (getWidth() + currentScrollX) - (this.scrollOffset * 2)) {
                int width = (newScrollX - getWidth()) + (this.scrollOffset * 3);
                this.lastScrollX = width;
                smoothScrollTo(width, 0);
            }
        }
    }

    @Override // android.widget.HorizontalScrollView, android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int l, int t, int r, int b) {
        super.onLayout(changed, l, t, r, b);
        setImages();
    }

    public void setImages() {
        ImageLocation imageLocation;
        ScrollSlidingTabStrip scrollSlidingTabStrip = this;
        int tabSize = AndroidUtilities.dp(52.0f);
        int start = getScrollX() / tabSize;
        int end = Math.min(scrollSlidingTabStrip.tabsContainer.getChildCount(), ((int) Math.ceil(getMeasuredWidth() / tabSize)) + start + 1);
        int a = start;
        while (a < end) {
            View child = scrollSlidingTabStrip.tabsContainer.getChildAt(a);
            Object object = child.getTag();
            Object parentObject = child.getTag(R.attr.parent_tag);
            TLRPC.Document sticker = (TLRPC.Document) child.getTag(R.attr.object_tag);
            if (object instanceof TLRPC.Document) {
                TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(sticker.thumbs, 90);
                ImageLocation imageLocation2 = ImageLocation.getForDocument(thumb, sticker);
                imageLocation = imageLocation2;
            } else if (!(object instanceof TLRPC.PhotoSize)) {
                a++;
                scrollSlidingTabStrip = this;
            } else {
                TLRPC.PhotoSize thumb2 = (TLRPC.PhotoSize) object;
                imageLocation = ImageLocation.getForSticker(thumb2, sticker);
            }
            if (imageLocation != null) {
                BackupImageView imageView = (BackupImageView) ((FrameLayout) child).getChildAt(0);
                if (!(object instanceof TLRPC.Document) || !MessageObject.isAnimatedStickerDocument(sticker)) {
                    ImageLocation imageLocation3 = imageLocation;
                    if (imageLocation3.lottieAnimation) {
                        imageView.setImage(imageLocation3, "30_30", "tgs", (Drawable) null, parentObject);
                    } else {
                        imageView.setImage(imageLocation3, (String) null, "webp", (Drawable) null, parentObject);
                    }
                } else {
                    imageView.setImage(ImageLocation.getForDocument(sticker), "30_30", imageLocation, null, 0, parentObject);
                }
            }
            a++;
            scrollSlidingTabStrip = this;
        }
    }

    @Override // android.view.View
    protected void onScrollChanged(int l, int t, int oldl, int oldt) {
        ImageLocation imageLocation;
        super.onScrollChanged(l, t, oldl, oldt);
        int tabSize = AndroidUtilities.dp(52.0f);
        int oldStart = oldl / tabSize;
        int newStart = l / tabSize;
        int count = ((int) Math.ceil(getMeasuredWidth() / tabSize)) + 1;
        int start = Math.max(0, Math.min(oldStart, newStart));
        int end = Math.min(this.tabsContainer.getChildCount(), Math.max(oldStart, newStart) + count);
        for (int a = start; a < end; a++) {
            View child = this.tabsContainer.getChildAt(a);
            if (child != null) {
                Object object = child.getTag();
                Object parentObject = child.getTag(R.attr.parent_tag);
                TLRPC.Document sticker = (TLRPC.Document) child.getTag(R.attr.object_tag);
                if (object instanceof TLRPC.Document) {
                    TLRPC.PhotoSize thumb = FileLoader.getClosestPhotoSizeWithSize(sticker.thumbs, 90);
                    ImageLocation imageLocation2 = ImageLocation.getForDocument(thumb, sticker);
                    imageLocation = imageLocation2;
                } else if (object instanceof TLRPC.PhotoSize) {
                    TLRPC.PhotoSize thumb2 = (TLRPC.PhotoSize) object;
                    imageLocation = ImageLocation.getForSticker(thumb2, sticker);
                }
                if (imageLocation != null) {
                    BackupImageView imageView = (BackupImageView) ((FrameLayout) child).getChildAt(0);
                    if (a < newStart || a >= newStart + count) {
                        BackupImageView imageView2 = imageView;
                        imageView2.setImageDrawable(null);
                    } else if ((object instanceof TLRPC.Document) && MessageObject.isAnimatedStickerDocument(sticker)) {
                        imageView.setImage(ImageLocation.getForDocument(sticker), "30_30", imageLocation, null, 0, parentObject);
                    } else {
                        ImageLocation imageLocation3 = imageLocation;
                        if (imageLocation3.lottieAnimation) {
                            imageView.setImage(imageLocation3, "30_30", "tgs", (Drawable) null, parentObject);
                        } else {
                            imageView.setImage(imageLocation3, (String) null, "webp", (Drawable) null, parentObject);
                        }
                    }
                }
            }
        }
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (isInEditMode() || this.tabCount == 0) {
            return;
        }
        int height = getHeight();
        if (this.underlineHeight > 0) {
            this.rectPaint.setColor(this.underlineColor);
            canvas.drawRect(0.0f, height - this.underlineHeight, this.tabsContainer.getWidth(), height, this.rectPaint);
        }
        if (this.indicatorHeight >= 0) {
            View currentTab = this.tabsContainer.getChildAt(this.currentPosition);
            float lineLeft = 0.0f;
            int width = 0;
            if (currentTab != null) {
                lineLeft = currentTab.getLeft();
                width = currentTab.getMeasuredWidth();
            }
            if (this.animateFromPosition) {
                long newTime = SystemClock.uptimeMillis();
                long dt = newTime - this.lastAnimationTime;
                this.lastAnimationTime = newTime;
                float f = this.positionAnimationProgress + (dt / 150.0f);
                this.positionAnimationProgress = f;
                if (f >= 1.0f) {
                    this.positionAnimationProgress = 1.0f;
                    this.animateFromPosition = false;
                }
                float f2 = this.startAnimationPosition;
                lineLeft = f2 + ((lineLeft - f2) * CubicBezierInterpolator.EASE_OUT_QUINT.getInterpolation(this.positionAnimationProgress));
                invalidate();
            }
            this.rectPaint.setColor(this.indicatorColor);
            if (this.indicatorHeight == 0) {
                canvas.drawRect(lineLeft, 0.0f, lineLeft + width, height, this.rectPaint);
            } else {
                canvas.drawRect(lineLeft, height - r4, lineLeft + width, height, this.rectPaint);
            }
        }
    }

    public void setShouldExpand(boolean value) {
        this.shouldExpand = value;
        requestLayout();
    }

    public int getCurrentPosition() {
        return this.currentPosition;
    }

    public void cancelPositionAnimation() {
        this.animateFromPosition = false;
        this.positionAnimationProgress = 1.0f;
    }

    public void onPageScrolled(int position, int first) {
        int i = this.currentPosition;
        if (i == position) {
            return;
        }
        View currentTab = this.tabsContainer.getChildAt(i);
        if (currentTab != null) {
            this.startAnimationPosition = currentTab.getLeft();
            this.positionAnimationProgress = 0.0f;
            this.animateFromPosition = true;
            this.lastAnimationTime = SystemClock.uptimeMillis();
        } else {
            this.animateFromPosition = false;
        }
        this.currentPosition = position;
        if (position >= this.tabsContainer.getChildCount()) {
            return;
        }
        this.positionAnimationProgress = 0.0f;
        int a = 0;
        while (a < this.tabsContainer.getChildCount()) {
            this.tabsContainer.getChildAt(a).setSelected(a == position);
            a++;
        }
        if (first == position && position > 1) {
            scrollToChild(position - 1);
        } else {
            scrollToChild(position);
        }
        invalidate();
    }

    public void setIndicatorHeight(int value) {
        this.indicatorHeight = value;
        invalidate();
    }

    public void setIndicatorColor(int value) {
        this.indicatorColor = value;
        invalidate();
    }

    public void setUnderlineColor(int value) {
        this.underlineColor = value;
        invalidate();
    }

    public void setUnderlineColorResource(int resId) {
        this.underlineColor = getResources().getColor(resId);
        invalidate();
    }

    public void setUnderlineHeight(int value) {
        this.underlineHeight = value;
        invalidate();
    }
}
