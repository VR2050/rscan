package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.Editable;
import android.text.TextPaint;
import android.text.TextWatcher;
import android.util.LongSparseArray;
import android.util.Property;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewOutlineProvider;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.MessagesStorage;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.ShareDialogCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ShareAlert extends BottomSheet implements NotificationCenter.NotificationCenterDelegate {
    private AnimatorSet animatorSet;
    private EditTextEmoji commentTextView;
    private boolean copyLinkOnEnd;
    private int currentAccount;
    private TLRPC.TL_exportedMessageLink exportedMessageLink;
    private FrameLayout frameLayout;
    private FrameLayout frameLayout2;
    private RecyclerListView gridView;
    private boolean isChannel;
    private GridLayoutManager layoutManager;
    private String linkToCopy;
    private ShareDialogsAdapter listAdapter;
    private boolean loadingLink;
    private Paint paint;
    private TextView pickerBottomLayout;
    private RectF rect;
    private int scrollOffsetY;
    private ShareSearchAdapter searchAdapter;
    private EmptyTextProgressView searchEmptyView;
    private View selectedCountView;
    private LongSparseArray<TLRPC.Dialog> selectedDialogs;
    private ArrayList<MessageObject> sendingMessageObjects;
    private String sendingText;
    private View[] shadow;
    private AnimatorSet[] shadowAnimation;
    private Drawable shadowDrawable;
    private TextPaint textPaint;
    private int topBeforeSwitch;
    private FrameLayout writeButtonContainer;

    /* JADX INFO: Access modifiers changed from: private */
    class SearchField extends FrameLayout {
        private View backgroundView;
        private ImageView clearSearchImageView;
        private CloseProgressDrawable2 progressDrawable;
        private View searchBackground;
        private EditTextBoldCursor searchEditText;
        private ImageView searchIconImageView;

        public SearchField(Context context) {
            super(context);
            View view = new View(context);
            this.searchBackground = view;
            view.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(18.0f), Theme.getColor(Theme.key_dialogSearchBackground)));
            addView(this.searchBackground, LayoutHelper.createFrame(-1.0f, 36.0f, 51, 14.0f, 11.0f, 14.0f, 0.0f));
            ImageView imageView = new ImageView(context);
            this.searchIconImageView = imageView;
            imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.searchIconImageView.setImageResource(R.drawable.smiles_inputsearch);
            this.searchIconImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogSearchIcon), PorterDuff.Mode.MULTIPLY));
            addView(this.searchIconImageView, LayoutHelper.createFrame(36.0f, 36.0f, 51, 16.0f, 11.0f, 0.0f, 0.0f));
            ImageView imageView2 = new ImageView(context);
            this.clearSearchImageView = imageView2;
            imageView2.setScaleType(ImageView.ScaleType.CENTER);
            ImageView imageView3 = this.clearSearchImageView;
            CloseProgressDrawable2 closeProgressDrawable2 = new CloseProgressDrawable2();
            this.progressDrawable = closeProgressDrawable2;
            imageView3.setImageDrawable(closeProgressDrawable2);
            this.progressDrawable.setSide(AndroidUtilities.dp(7.0f));
            this.clearSearchImageView.setScaleX(0.1f);
            this.clearSearchImageView.setScaleY(0.1f);
            this.clearSearchImageView.setAlpha(0.0f);
            this.clearSearchImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogSearchIcon), PorterDuff.Mode.MULTIPLY));
            addView(this.clearSearchImageView, LayoutHelper.createFrame(36.0f, 36.0f, 53, 14.0f, 11.0f, 14.0f, 0.0f));
            this.clearSearchImageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ShareAlert$SearchField$pSR1EDweqEJPWYmUq6mMbJ5NFr4
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$new$0$ShareAlert$SearchField(view2);
                }
            });
            EditTextBoldCursor editTextBoldCursor = new EditTextBoldCursor(context) { // from class: im.uwrkaxlmjj.ui.components.ShareAlert.SearchField.1
                @Override // android.view.View
                public boolean dispatchTouchEvent(MotionEvent event) {
                    MotionEvent e = MotionEvent.obtain(event);
                    e.setLocation(e.getRawX(), e.getRawY() - ShareAlert.this.containerView.getTranslationY());
                    ShareAlert.this.gridView.dispatchTouchEvent(e);
                    e.recycle();
                    return super.dispatchTouchEvent(event);
                }
            };
            this.searchEditText = editTextBoldCursor;
            editTextBoldCursor.setTextSize(1, 16.0f);
            this.searchEditText.setHintTextColor(Theme.getColor(Theme.key_dialogSearchHint));
            this.searchEditText.setTextColor(Theme.getColor(Theme.key_dialogSearchText));
            this.searchEditText.setBackgroundDrawable(null);
            this.searchEditText.setPadding(0, 0, 0, 0);
            this.searchEditText.setMaxLines(1);
            this.searchEditText.setLines(1);
            this.searchEditText.setSingleLine(true);
            this.searchEditText.setImeOptions(268435459);
            this.searchEditText.setHint(LocaleController.getString("ShareSendTo", R.string.ShareSendTo));
            this.searchEditText.setCursorColor(Theme.getColor(Theme.key_featuredStickers_addedIcon));
            this.searchEditText.setCursorSize(AndroidUtilities.dp(20.0f));
            this.searchEditText.setCursorWidth(1.5f);
            addView(this.searchEditText, LayoutHelper.createFrame(-1.0f, 40.0f, 51, 54.0f, 9.0f, 46.0f, 0.0f));
            this.searchEditText.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.components.ShareAlert.SearchField.2
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable s) {
                    boolean show = SearchField.this.searchEditText.length() > 0;
                    boolean showed = SearchField.this.clearSearchImageView.getAlpha() != 0.0f;
                    if (show != showed) {
                        SearchField.this.clearSearchImageView.animate().alpha(show ? 1.0f : 0.0f).setDuration(150L).scaleX(show ? 1.0f : 0.1f).scaleY(show ? 1.0f : 0.1f).start();
                    }
                    String text = SearchField.this.searchEditText.getText().toString();
                    if (text.length() != 0) {
                        if (ShareAlert.this.searchEmptyView != null) {
                            ShareAlert.this.searchEmptyView.setText(LocaleController.getString("NoResult", R.string.NoResult));
                        }
                    } else if (ShareAlert.this.gridView.getAdapter() != ShareAlert.this.listAdapter) {
                        int top = ShareAlert.this.getCurrentTop();
                        ShareAlert.this.searchEmptyView.setText(LocaleController.getString("NoChats", R.string.NoChats));
                        ShareAlert.this.searchEmptyView.showTextView();
                        ShareAlert.this.gridView.setAdapter(ShareAlert.this.listAdapter);
                        ShareAlert.this.listAdapter.notifyDataSetChanged();
                        if (top > 0) {
                            ShareAlert.this.layoutManager.scrollToPositionWithOffset(0, -top);
                        }
                    }
                    if (ShareAlert.this.searchAdapter != null) {
                        ShareAlert.this.searchAdapter.searchDialogs(text);
                    }
                }
            });
            this.searchEditText.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ShareAlert$SearchField$k-zY8px6_k6Nt8f8FTiJAv0jjzs
                @Override // android.widget.TextView.OnEditorActionListener
                public final boolean onEditorAction(TextView textView, int i, KeyEvent keyEvent) {
                    return this.f$0.lambda$new$1$ShareAlert$SearchField(textView, i, keyEvent);
                }
            });
        }

        public /* synthetic */ void lambda$new$0$ShareAlert$SearchField(View v) {
            this.searchEditText.setText("");
            AndroidUtilities.showKeyboard(this.searchEditText);
        }

        public /* synthetic */ boolean lambda$new$1$ShareAlert$SearchField(TextView v, int actionId, KeyEvent event) {
            if (event == null) {
                return false;
            }
            if ((event.getAction() == 1 && event.getKeyCode() == 84) || (event.getAction() == 0 && event.getKeyCode() == 66)) {
                AndroidUtilities.hideKeyboard(this.searchEditText);
                return false;
            }
            return false;
        }

        public void hideKeyboard() {
            AndroidUtilities.hideKeyboard(this.searchEditText);
        }

        @Override // android.view.ViewGroup, android.view.ViewParent
        public void requestDisallowInterceptTouchEvent(boolean disallowIntercept) {
            super.requestDisallowInterceptTouchEvent(disallowIntercept);
        }
    }

    public static ShareAlert createShareAlert(Context context, MessageObject messageObject, String text, boolean channel, String copyLink, boolean fullScreen) {
        ArrayList<MessageObject> arrayList;
        if (messageObject != null) {
            arrayList = new ArrayList<>();
            arrayList.add(messageObject);
        } else {
            arrayList = null;
        }
        return new ShareAlert(context, arrayList, text, channel, copyLink, fullScreen);
    }

    public ShareAlert(final Context context, ArrayList<MessageObject> messages, String text, boolean channel, String copyLink, boolean fullScreen) {
        TLRPC.Chat chat;
        super(context, true, 1);
        this.shadow = new View[2];
        this.shadowAnimation = new AnimatorSet[2];
        this.selectedDialogs = new LongSparseArray<>();
        this.rect = new RectF();
        this.paint = new Paint(1);
        this.textPaint = new TextPaint(1);
        this.currentAccount = UserConfig.selectedAccount;
        Drawable drawableMutate = context.getResources().getDrawable(R.drawable.sheet_shadow_round).mutate();
        this.shadowDrawable = drawableMutate;
        drawableMutate.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogBackground), PorterDuff.Mode.MULTIPLY));
        this.isFullscreen = fullScreen;
        this.linkToCopy = copyLink;
        this.sendingMessageObjects = messages;
        this.searchAdapter = new ShareSearchAdapter(context);
        this.isChannel = channel;
        this.sendingText = text;
        if (channel) {
            this.loadingLink = true;
            TLRPC.TL_channels_exportMessageLinkV2 req = new TLRPC.TL_channels_exportMessageLinkV2();
            req.id = messages.get(0).getId();
            req.channel = MessagesController.getInstance(this.currentAccount).getInputChannel(messages.get(0).messageOwner.to_id.channel_id);
            if (messages.get(0).messageOwner.from_id < 0 && (chat = MessagesController.getInstance(this.currentAccount).getChat(Integer.valueOf(-messages.get(0).messageOwner.from_id))) != null) {
                req.isGroup = chat.megagroup;
            }
            ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ShareAlert$thmB8JJIyrUvj9sKOBe4hU3qzF8
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$new$1$ShareAlert(context, tLObject, tL_error);
                }
            });
        }
        SizeNotifierFrameLayout sizeNotifierFrameLayout = new SizeNotifierFrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.ShareAlert.1
            private boolean fullHeight;
            private boolean ignoreLayout = false;
            private RectF rect1 = new RectF();

            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int totalHeight = View.MeasureSpec.getSize(heightMeasureSpec);
                if (Build.VERSION.SDK_INT >= 21 && !ShareAlert.this.isFullscreen) {
                    this.ignoreLayout = true;
                    setPadding(ShareAlert.this.backgroundPaddingLeft, AndroidUtilities.statusBarHeight, ShareAlert.this.backgroundPaddingLeft, 0);
                    this.ignoreLayout = false;
                }
                int availableHeight = totalHeight - getPaddingTop();
                int keyboardSize = getKeyboardHeight();
                if (!AndroidUtilities.isInMultiwindow && keyboardSize <= AndroidUtilities.dp(20.0f)) {
                    availableHeight -= ShareAlert.this.commentTextView.getEmojiPadding();
                }
                int size = Math.max(ShareAlert.this.searchAdapter.getItemCount(), ShareAlert.this.listAdapter.getItemCount());
                int contentSize = AndroidUtilities.dp(48.0f) + (Math.max(3, (int) Math.ceil(size / 4.0f)) * AndroidUtilities.dp(103.0f)) + ShareAlert.this.backgroundPaddingTop;
                int padding = (contentSize < availableHeight ? 0 : availableHeight - ((availableHeight / 5) * 3)) + AndroidUtilities.dp(8.0f);
                if (ShareAlert.this.gridView.getPaddingTop() != padding) {
                    this.ignoreLayout = true;
                    ShareAlert.this.gridView.setPadding(0, padding, 0, AndroidUtilities.dp(48.0f));
                    this.ignoreLayout = false;
                }
                this.fullHeight = contentSize >= totalHeight;
                onMeasureInternal(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(Math.min(contentSize, totalHeight), 1073741824));
            }

            private void onMeasureInternal(int widthMeasureSpec, int heightMeasureSpec) {
                int visibility;
                int heightSize;
                int heightMeasureSpec2;
                int widthSize = View.MeasureSpec.getSize(widthMeasureSpec);
                int heightSize2 = View.MeasureSpec.getSize(heightMeasureSpec);
                setMeasuredDimension(widthSize, heightSize2);
                int widthSize2 = widthSize - (ShareAlert.this.backgroundPaddingLeft * 2);
                int keyboardSize = getKeyboardHeight();
                if (keyboardSize <= AndroidUtilities.dp(20.0f)) {
                    if (!AndroidUtilities.isInMultiwindow) {
                        heightSize2 -= ShareAlert.this.commentTextView.getEmojiPadding();
                        heightMeasureSpec2 = View.MeasureSpec.makeMeasureSpec(heightSize2, 1073741824);
                    } else {
                        heightMeasureSpec2 = heightMeasureSpec;
                    }
                    this.ignoreLayout = true;
                    int visibility2 = ShareAlert.this.commentTextView.isPopupShowing() ? 8 : 0;
                    if (ShareAlert.this.pickerBottomLayout != null) {
                        ShareAlert.this.pickerBottomLayout.setVisibility(visibility2);
                        View view = ShareAlert.this.shadow[1];
                        if (ShareAlert.this.frameLayout2.getVisibility() != 0 && visibility2 != 0) {
                            f = 0.0f;
                        }
                        view.setAlpha(f);
                    }
                    this.ignoreLayout = false;
                    visibility = heightMeasureSpec2;
                    heightSize = heightSize2;
                } else {
                    this.ignoreLayout = true;
                    ShareAlert.this.commentTextView.hideEmojiView();
                    if (ShareAlert.this.pickerBottomLayout != null) {
                        ShareAlert.this.pickerBottomLayout.setVisibility(8);
                        ShareAlert.this.shadow[1].setAlpha(ShareAlert.this.frameLayout2.getVisibility() != 0 ? 0.0f : 1.0f);
                    }
                    this.ignoreLayout = false;
                    visibility = heightMeasureSpec;
                    heightSize = heightSize2;
                }
                int childCount = getChildCount();
                for (int i = 0; i < childCount; i++) {
                    View child = getChildAt(i);
                    if (child != null && child.getVisibility() != 8) {
                        if (ShareAlert.this.commentTextView != null && ShareAlert.this.commentTextView.isPopupView(child)) {
                            if (AndroidUtilities.isInMultiwindow || AndroidUtilities.isTablet()) {
                                if (AndroidUtilities.isTablet()) {
                                    child.measure(View.MeasureSpec.makeMeasureSpec(widthSize2, 1073741824), View.MeasureSpec.makeMeasureSpec(Math.min(AndroidUtilities.dp(AndroidUtilities.isTablet() ? 200.0f : 320.0f), (heightSize - AndroidUtilities.statusBarHeight) + getPaddingTop()), 1073741824));
                                } else {
                                    child.measure(View.MeasureSpec.makeMeasureSpec(widthSize2, 1073741824), View.MeasureSpec.makeMeasureSpec((heightSize - AndroidUtilities.statusBarHeight) + getPaddingTop(), 1073741824));
                                }
                            } else {
                                child.measure(View.MeasureSpec.makeMeasureSpec(widthSize2, 1073741824), View.MeasureSpec.makeMeasureSpec(child.getLayoutParams().height, 1073741824));
                            }
                        } else {
                            measureChildWithMargins(child, widthMeasureSpec, 0, visibility, 0);
                        }
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout, android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int l, int t, int r, int b) {
                int childLeft;
                int childTop;
                int count = getChildCount();
                int paddingBottom = (getKeyboardHeight() > AndroidUtilities.dp(20.0f) || AndroidUtilities.isInMultiwindow || AndroidUtilities.isTablet()) ? 0 : ShareAlert.this.commentTextView.getEmojiPadding();
                setBottomClip(paddingBottom);
                for (int i = 0; i < count; i++) {
                    View child = getChildAt(i);
                    if (child.getVisibility() != 8) {
                        FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) child.getLayoutParams();
                        int width = child.getMeasuredWidth();
                        int height = child.getMeasuredHeight();
                        int gravity = lp.gravity;
                        if (gravity == -1) {
                            gravity = 51;
                        }
                        int absoluteGravity = gravity & 7;
                        int verticalGravity = gravity & 112;
                        int i2 = absoluteGravity & 7;
                        if (i2 == 1) {
                            int childLeft2 = r - l;
                            childLeft = (((childLeft2 - width) / 2) + lp.leftMargin) - lp.rightMargin;
                        } else if (i2 == 5) {
                            int childLeft3 = r - l;
                            childLeft = (((childLeft3 - width) - lp.rightMargin) - getPaddingRight()) - ShareAlert.this.backgroundPaddingLeft;
                        } else {
                            childLeft = lp.leftMargin + getPaddingLeft();
                        }
                        if (verticalGravity == 16) {
                            int childTop2 = b - paddingBottom;
                            childTop = ((((childTop2 - t) - height) / 2) + lp.topMargin) - lp.bottomMargin;
                        } else if (verticalGravity == 48) {
                            int childTop3 = lp.topMargin;
                            childTop = childTop3 + getPaddingTop();
                        } else if (verticalGravity == 80) {
                            int childTop4 = b - paddingBottom;
                            childTop = ((childTop4 - t) - height) - lp.bottomMargin;
                        } else {
                            childTop = lp.topMargin;
                        }
                        if (ShareAlert.this.commentTextView != null && ShareAlert.this.commentTextView.isPopupView(child)) {
                            if (AndroidUtilities.isTablet()) {
                                childTop = getMeasuredHeight() - child.getMeasuredHeight();
                            } else {
                                childTop = (getMeasuredHeight() + getKeyboardHeight()) - child.getMeasuredHeight();
                            }
                        }
                        child.layout(childLeft, childTop, childLeft + width, childTop + height);
                    }
                }
                notifyHeightChanged();
                ShareAlert.this.updateLayout();
            }

            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                if (ev.getAction() == 0 && ShareAlert.this.scrollOffsetY != 0 && ev.getY() < ShareAlert.this.scrollOffsetY - AndroidUtilities.dp(30.0f)) {
                    ShareAlert.this.dismiss();
                    return true;
                }
                return super.onInterceptTouchEvent(ev);
            }

            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent e) {
                return !ShareAlert.this.isDismissed() && super.onTouchEvent(e);
            }

            @Override // android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }

            @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout, android.view.View
            protected void onDraw(Canvas canvas) {
                int y;
                int top;
                int height;
                int statusBarHeight;
                float radProgress;
                int y2 = (ShareAlert.this.scrollOffsetY - ShareAlert.this.backgroundPaddingTop) + AndroidUtilities.dp(6.0f);
                int top2 = (ShareAlert.this.scrollOffsetY - ShareAlert.this.backgroundPaddingTop) - AndroidUtilities.dp(13.0f);
                int height2 = getMeasuredHeight() + AndroidUtilities.dp(30.0f) + ShareAlert.this.backgroundPaddingTop;
                float radProgress2 = 1.0f;
                if (!ShareAlert.this.isFullscreen && Build.VERSION.SDK_INT >= 21) {
                    int top3 = top2 + AndroidUtilities.statusBarHeight;
                    int y3 = y2 + AndroidUtilities.statusBarHeight;
                    int height3 = height2 - AndroidUtilities.statusBarHeight;
                    if (this.fullHeight) {
                        if (ShareAlert.this.backgroundPaddingTop + top3 < AndroidUtilities.statusBarHeight * 2) {
                            int diff = Math.min(AndroidUtilities.statusBarHeight, ((AndroidUtilities.statusBarHeight * 2) - top3) - ShareAlert.this.backgroundPaddingTop);
                            top3 -= diff;
                            height3 += diff;
                            radProgress2 = 1.0f - Math.min(1.0f, (diff * 2) / AndroidUtilities.statusBarHeight);
                        }
                        if (ShareAlert.this.backgroundPaddingTop + top3 < AndroidUtilities.statusBarHeight) {
                            int statusBarHeight2 = Math.min(AndroidUtilities.statusBarHeight, (AndroidUtilities.statusBarHeight - top3) - ShareAlert.this.backgroundPaddingTop);
                            y = y3;
                            top = top3;
                            height = height3;
                            statusBarHeight = statusBarHeight2;
                            radProgress = radProgress2;
                        } else {
                            y = y3;
                            top = top3;
                            height = height3;
                            statusBarHeight = 0;
                            radProgress = radProgress2;
                        }
                    } else {
                        y = y3;
                        top = top3;
                        height = height3;
                        statusBarHeight = 0;
                        radProgress = 1.0f;
                    }
                } else {
                    y = y2;
                    top = top2;
                    height = height2;
                    statusBarHeight = 0;
                    radProgress = 1.0f;
                }
                ShareAlert.this.shadowDrawable.setBounds(0, top, getMeasuredWidth(), height);
                ShareAlert.this.shadowDrawable.draw(canvas);
                if (radProgress != 1.0f) {
                    Theme.dialogs_onlineCirclePaint.setColor(Theme.getColor(Theme.key_dialogBackground));
                    this.rect1.set(ShareAlert.this.backgroundPaddingLeft, ShareAlert.this.backgroundPaddingTop + top, getMeasuredWidth() - ShareAlert.this.backgroundPaddingLeft, ShareAlert.this.backgroundPaddingTop + top + AndroidUtilities.dp(24.0f));
                    canvas.drawRoundRect(this.rect1, AndroidUtilities.dp(12.0f) * radProgress, AndroidUtilities.dp(12.0f) * radProgress, Theme.dialogs_onlineCirclePaint);
                }
                int w = AndroidUtilities.dp(36.0f);
                this.rect1.set((getMeasuredWidth() - w) / 2, y, (getMeasuredWidth() + w) / 2, AndroidUtilities.dp(4.0f) + y);
                Theme.dialogs_onlineCirclePaint.setColor(Theme.getColor(Theme.key_sheet_scrollUp));
                canvas.drawRoundRect(this.rect1, AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), Theme.dialogs_onlineCirclePaint);
                if (statusBarHeight > 0) {
                    int color1 = Theme.getColor(Theme.key_dialogBackground);
                    int finalColor = Color.argb(255, (int) (Color.red(color1) * 0.8f), (int) (Color.green(color1) * 0.8f), (int) (Color.blue(color1) * 0.8f));
                    Theme.dialogs_onlineCirclePaint.setColor(finalColor);
                    canvas.drawRect(ShareAlert.this.backgroundPaddingLeft, AndroidUtilities.statusBarHeight - statusBarHeight, getMeasuredWidth() - ShareAlert.this.backgroundPaddingLeft, AndroidUtilities.statusBarHeight, Theme.dialogs_onlineCirclePaint);
                }
            }
        };
        this.containerView = sizeNotifierFrameLayout;
        this.containerView.setWillNotDraw(false);
        this.containerView.setPadding(this.backgroundPaddingLeft, 0, this.backgroundPaddingLeft, 0);
        FrameLayout frameLayout = new FrameLayout(context);
        this.frameLayout = frameLayout;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        final SearchField searchView = new SearchField(context);
        this.frameLayout.addView(searchView, LayoutHelper.createFrame(-1, -1, 51));
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.components.ShareAlert.2
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView
            protected boolean allowSelectChildAtPosition(float x, float y) {
                return y >= ((float) ((ShareAlert.this.scrollOffsetY + AndroidUtilities.dp(48.0f)) + (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)));
            }
        };
        this.gridView = recyclerListView;
        recyclerListView.setTag(13);
        this.gridView.setPadding(0, 0, 0, AndroidUtilities.dp(48.0f));
        this.gridView.setClipToPadding(false);
        RecyclerListView recyclerListView2 = this.gridView;
        GridLayoutManager gridLayoutManager = new GridLayoutManager(getContext(), 4);
        this.layoutManager = gridLayoutManager;
        recyclerListView2.setLayoutManager(gridLayoutManager);
        this.layoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.components.ShareAlert.3
            @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
            public int getSpanSize(int position) {
                if (position == 0) {
                    return ShareAlert.this.layoutManager.getSpanCount();
                }
                return 1;
            }
        });
        this.gridView.setHorizontalScrollBarEnabled(false);
        this.gridView.setVerticalScrollBarEnabled(false);
        this.gridView.addItemDecoration(new RecyclerView.ItemDecoration() { // from class: im.uwrkaxlmjj.ui.components.ShareAlert.4
            @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
            public void getItemOffsets(android.graphics.Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
                RecyclerListView.Holder holder = (RecyclerListView.Holder) parent.getChildViewHolder(view);
                if (holder != null) {
                    int pos = holder.getAdapterPosition();
                    outRect.left = pos % 4 == 0 ? 0 : AndroidUtilities.dp(4.0f);
                    outRect.right = pos % 4 != 3 ? AndroidUtilities.dp(4.0f) : 0;
                } else {
                    outRect.left = AndroidUtilities.dp(4.0f);
                    outRect.right = AndroidUtilities.dp(4.0f);
                }
            }
        });
        this.containerView.addView(this.gridView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, 0.0f));
        RecyclerListView recyclerListView3 = this.gridView;
        ShareDialogsAdapter shareDialogsAdapter = new ShareDialogsAdapter(context);
        this.listAdapter = shareDialogsAdapter;
        recyclerListView3.setAdapter(shareDialogsAdapter);
        this.gridView.setGlowColor(Theme.getColor(Theme.key_dialogScrollGlow));
        this.gridView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ShareAlert$RLQyLikRbX0LjMo4wWzTbKhwGOM
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$new$2$ShareAlert(searchView, view, i);
            }
        });
        this.gridView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.ShareAlert.5
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                ShareAlert.this.updateLayout();
            }
        });
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.searchEmptyView = emptyTextProgressView;
        emptyTextProgressView.setShowAtCenter(true);
        this.searchEmptyView.showTextView();
        this.searchEmptyView.setText(LocaleController.getString("NoChats", R.string.NoChats));
        this.gridView.setEmptyView(this.searchEmptyView);
        this.containerView.addView(this.searchEmptyView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 52.0f, 0.0f, 0.0f));
        FrameLayout.LayoutParams frameLayoutParams = new FrameLayout.LayoutParams(-1, AndroidUtilities.getShadowHeight(), 51);
        frameLayoutParams.topMargin = AndroidUtilities.dp(58.0f);
        this.shadow[0] = new View(context);
        this.shadow[0].setBackgroundColor(Theme.getColor(Theme.key_dialogShadowLine));
        this.shadow[0].setAlpha(0.0f);
        this.shadow[0].setTag(1);
        this.containerView.addView(this.shadow[0], frameLayoutParams);
        this.containerView.addView(this.frameLayout, LayoutHelper.createFrame(-1, 58, 51));
        FrameLayout.LayoutParams frameLayoutParams2 = new FrameLayout.LayoutParams(-1, AndroidUtilities.getShadowHeight(), 83);
        frameLayoutParams2.bottomMargin = AndroidUtilities.dp(48.0f);
        this.shadow[1] = new View(context);
        this.shadow[1].setBackgroundColor(Theme.getColor(Theme.key_dialogShadowLine));
        this.containerView.addView(this.shadow[1], frameLayoutParams2);
        if (this.isChannel || this.linkToCopy != null) {
            TextView textView = new TextView(context);
            this.pickerBottomLayout = textView;
            textView.setBackgroundDrawable(Theme.createSelectorWithBackgroundDrawable(Theme.getColor(Theme.key_dialogBackground), Theme.getColor(Theme.key_listSelector)));
            this.pickerBottomLayout.setTextColor(Theme.getColor(Theme.key_dialogTextBlue2));
            this.pickerBottomLayout.setTextSize(1, 14.0f);
            this.pickerBottomLayout.setPadding(AndroidUtilities.dp(18.0f), 0, AndroidUtilities.dp(18.0f), 0);
            this.pickerBottomLayout.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.pickerBottomLayout.setGravity(17);
            this.pickerBottomLayout.setText(LocaleController.getString("CopyLink", R.string.CopyLink).toUpperCase());
            this.pickerBottomLayout.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ShareAlert$TfvCuG48mnr6H3XJT1m21gEQ6JQ
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$3$ShareAlert(view);
                }
            });
            this.containerView.addView(this.pickerBottomLayout, LayoutHelper.createFrame(-1, 48, 83));
        } else {
            this.shadow[1].setAlpha(0.0f);
        }
        FrameLayout frameLayout2 = new FrameLayout(context);
        this.frameLayout2 = frameLayout2;
        frameLayout2.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        this.frameLayout2.setAlpha(0.0f);
        this.frameLayout2.setVisibility(4);
        this.containerView.addView(this.frameLayout2, LayoutHelper.createFrame(-1, 48, 83));
        this.frameLayout2.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ShareAlert$Eg-C8xhp75Gn4lOIe-zCn7IuLNw
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return ShareAlert.lambda$new$4(view, motionEvent);
            }
        });
        EditTextEmoji editTextEmoji = new EditTextEmoji(context, sizeNotifierFrameLayout, null, 1);
        this.commentTextView = editTextEmoji;
        editTextEmoji.setHint(LocaleController.getString("ShareComment", R.string.ShareComment));
        this.commentTextView.onResume();
        EditTextBoldCursor editText = this.commentTextView.getEditText();
        editText.setMaxLines(1);
        editText.setSingleLine(true);
        this.frameLayout2.addView(this.commentTextView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 84.0f, 0.0f));
        FrameLayout frameLayout3 = new FrameLayout(context);
        this.writeButtonContainer = frameLayout3;
        frameLayout3.setVisibility(4);
        this.writeButtonContainer.setScaleX(0.2f);
        this.writeButtonContainer.setScaleY(0.2f);
        this.writeButtonContainer.setAlpha(0.0f);
        this.writeButtonContainer.setContentDescription(LocaleController.getString("Send", R.string.Send));
        this.containerView.addView(this.writeButtonContainer, LayoutHelper.createFrame(60.0f, 60.0f, 85, 0.0f, 0.0f, 6.0f, 10.0f));
        this.writeButtonContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ShareAlert$p_Ek2SmXYlSXaFnYCTsQoFJewRQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$5$ShareAlert(view);
            }
        });
        ImageView writeButton = new ImageView(context);
        Drawable drawable = Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(56.0f), Theme.getColor(Theme.key_dialogFloatingButton), Theme.getColor(Theme.key_dialogFloatingButtonPressed));
        if (Build.VERSION.SDK_INT < 21) {
            Drawable shadowDrawable = context.getResources().getDrawable(R.drawable.floating_shadow_profile).mutate();
            shadowDrawable.setColorFilter(new PorterDuffColorFilter(-16777216, PorterDuff.Mode.MULTIPLY));
            CombinedDrawable combinedDrawable = new CombinedDrawable(shadowDrawable, drawable, 0, 0);
            combinedDrawable.setIconSize(AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
            drawable = combinedDrawable;
        }
        writeButton.setBackgroundDrawable(drawable);
        writeButton.setImageResource(R.drawable.attach_send);
        writeButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogFloatingIcon), PorterDuff.Mode.MULTIPLY));
        writeButton.setScaleType(ImageView.ScaleType.CENTER);
        if (Build.VERSION.SDK_INT >= 21) {
            writeButton.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.components.ShareAlert.6
                @Override // android.view.ViewOutlineProvider
                public void getOutline(View view, Outline outline) {
                    outline.setOval(0, 0, AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
                }
            });
        }
        this.writeButtonContainer.addView(writeButton, LayoutHelper.createFrame(Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, 51, Build.VERSION.SDK_INT >= 21 ? 2.0f : 0.0f, 0.0f, 0.0f, 0.0f));
        this.textPaint.setTextSize(AndroidUtilities.dp(12.0f));
        this.textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        View view = new View(context) { // from class: im.uwrkaxlmjj.ui.components.ShareAlert.7
            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                String text2 = String.format("%d", Integer.valueOf(Math.max(1, ShareAlert.this.selectedDialogs.size())));
                int textSize = (int) Math.ceil(ShareAlert.this.textPaint.measureText(text2));
                int size = Math.max(AndroidUtilities.dp(16.0f) + textSize, AndroidUtilities.dp(24.0f));
                int cx = getMeasuredWidth() / 2;
                int measuredHeight = getMeasuredHeight() / 2;
                ShareAlert.this.textPaint.setColor(Theme.getColor(Theme.key_dialogRoundCheckBoxCheck));
                ShareAlert.this.paint.setColor(Theme.getColor(Theme.key_dialogBackground));
                ShareAlert.this.rect.set(cx - (size / 2), 0.0f, (size / 2) + cx, getMeasuredHeight());
                canvas.drawRoundRect(ShareAlert.this.rect, AndroidUtilities.dp(12.0f), AndroidUtilities.dp(12.0f), ShareAlert.this.paint);
                ShareAlert.this.paint.setColor(Theme.getColor(Theme.key_dialogRoundCheckBox));
                ShareAlert.this.rect.set((cx - (size / 2)) + AndroidUtilities.dp(2.0f), AndroidUtilities.dp(2.0f), ((size / 2) + cx) - AndroidUtilities.dp(2.0f), getMeasuredHeight() - AndroidUtilities.dp(2.0f));
                canvas.drawRoundRect(ShareAlert.this.rect, AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), ShareAlert.this.paint);
                canvas.drawText(text2, cx - (textSize / 2), AndroidUtilities.dp(16.2f), ShareAlert.this.textPaint);
            }
        };
        this.selectedCountView = view;
        view.setAlpha(0.0f);
        this.selectedCountView.setScaleX(0.2f);
        this.selectedCountView.setScaleY(0.2f);
        this.containerView.addView(this.selectedCountView, LayoutHelper.createFrame(42.0f, 24.0f, 85, 0.0f, 0.0f, -8.0f, 9.0f));
        updateSelectedCount(0);
        boolean[] zArr = DialogsActivity.dialogsLoaded;
        int i = this.currentAccount;
        if (!zArr[i]) {
            MessagesController.getInstance(i).loadDialogs(0, 0, 100, true);
            ContactsController.getInstance(this.currentAccount).checkInviteText();
            DialogsActivity.dialogsLoaded[this.currentAccount] = true;
        }
        if (this.listAdapter.dialogs.isEmpty()) {
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.dialogsNeedReload);
        }
    }

    public /* synthetic */ void lambda$new$1$ShareAlert(final Context context, final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ShareAlert$yKX6H_WtwWLLVVqhBkP4YF8NQbk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$ShareAlert(response, context);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$ShareAlert(TLObject response, Context context) {
        if (response != null) {
            this.exportedMessageLink = (TLRPC.TL_exportedMessageLink) response;
            if (this.copyLinkOnEnd) {
                copyLink(context);
            }
        }
        this.loadingLink = false;
    }

    public /* synthetic */ void lambda$new$2$ShareAlert(SearchField searchField, View view, int i) {
        TLRPC.Dialog item;
        if (i < 0) {
            return;
        }
        RecyclerView.Adapter adapter = this.gridView.getAdapter();
        ShareDialogsAdapter shareDialogsAdapter = this.listAdapter;
        if (adapter == shareDialogsAdapter) {
            item = shareDialogsAdapter.getItem(i);
        } else {
            item = this.searchAdapter.getItem(i);
        }
        if (item == null) {
            return;
        }
        ShareDialogCell shareDialogCell = (ShareDialogCell) view;
        if (this.selectedDialogs.indexOfKey(item.id) >= 0) {
            this.selectedDialogs.remove(item.id);
            shareDialogCell.setChecked(false, true);
            updateSelectedCount(1);
            return;
        }
        this.selectedDialogs.put(item.id, item);
        shareDialogCell.setChecked(true, true);
        updateSelectedCount(2);
        int i2 = UserConfig.getInstance(this.currentAccount).clientUserId;
        if (this.gridView.getAdapter() != this.searchAdapter) {
            return;
        }
        TLRPC.Dialog dialog = (TLRPC.Dialog) this.listAdapter.dialogsMap.get(item.id);
        if (dialog == null) {
            this.listAdapter.dialogsMap.put(item.id, item);
            this.listAdapter.dialogs.add(1 ^ (this.listAdapter.dialogs.isEmpty() ? 1 : 0), item);
        } else if (dialog.id != i2) {
            this.listAdapter.dialogs.remove(dialog);
            this.listAdapter.dialogs.add(1 ^ (this.listAdapter.dialogs.isEmpty() ? 1 : 0), dialog);
        }
        searchField.searchEditText.setText("");
        this.gridView.setAdapter(this.listAdapter);
        searchField.hideKeyboard();
    }

    public /* synthetic */ void lambda$new$3$ShareAlert(View v) {
        if (this.selectedDialogs.size() == 0) {
            if (this.isChannel || this.linkToCopy != null) {
                if (this.linkToCopy == null && this.loadingLink) {
                    this.copyLinkOnEnd = true;
                    ToastUtils.show(R.string.Loading);
                } else {
                    copyLink(getContext());
                }
                dismiss();
            }
        }
    }

    static /* synthetic */ boolean lambda$new$4(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$new$5$ShareAlert(View v) {
        for (int a = 0; a < this.selectedDialogs.size(); a++) {
            if (AlertsCreator.checkSlowMode(getContext(), this.currentAccount, this.selectedDialogs.keyAt(a), this.frameLayout2.getTag() != null && this.commentTextView.length() > 0)) {
                return;
            }
        }
        if (this.sendingMessageObjects != null) {
            for (int a2 = 0; a2 < this.selectedDialogs.size(); a2++) {
                long key = this.selectedDialogs.keyAt(a2);
                if (this.frameLayout2.getTag() != null && this.commentTextView.length() > 0) {
                    SendMessagesHelper.getInstance(this.currentAccount).sendMessage(this.commentTextView.getText().toString(), key, null, null, true, null, null, null, true, 0);
                }
                SendMessagesHelper.getInstance(this.currentAccount).sendMessage(this.sendingMessageObjects, key, true, 0);
            }
        } else if (this.sendingText != null) {
            for (int a3 = 0; a3 < this.selectedDialogs.size(); a3++) {
                long key2 = this.selectedDialogs.keyAt(a3);
                if (this.frameLayout2.getTag() != null && this.commentTextView.length() > 0) {
                    SendMessagesHelper.getInstance(this.currentAccount).sendMessage(this.commentTextView.getText().toString(), key2, null, null, true, null, null, null, true, 0);
                }
                SendMessagesHelper.getInstance(this.currentAccount).sendMessage(this.sendingText, key2, null, null, true, null, null, null, true, 0);
            }
        }
        dismiss();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int getCurrentTop() {
        if (this.gridView.getChildCount() != 0) {
            int top = 0;
            View child = this.gridView.getChildAt(0);
            RecyclerListView.Holder holder = (RecyclerListView.Holder) this.gridView.findContainingViewHolder(child);
            if (holder != null) {
                int paddingTop = this.gridView.getPaddingTop();
                if (holder.getAdapterPosition() == 0 && child.getTop() >= 0) {
                    top = child.getTop();
                }
                return paddingTop - top;
            }
            return -1000;
        }
        return -1000;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    public void dismissInternal() {
        super.dismissInternal();
        EditTextEmoji editTextEmoji = this.commentTextView;
        if (editTextEmoji != null) {
            editTextEmoji.onDestroy();
        }
    }

    @Override // android.app.Dialog
    public void onBackPressed() {
        EditTextEmoji editTextEmoji = this.commentTextView;
        if (editTextEmoji != null && editTextEmoji.isPopupShowing()) {
            this.commentTextView.hidePopup(true);
        } else {
            super.onBackPressed();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.dialogsNeedReload) {
            ShareDialogsAdapter shareDialogsAdapter = this.listAdapter;
            if (shareDialogsAdapter != null) {
                shareDialogsAdapter.fetchDialogs();
            }
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.dialogsNeedReload);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithSwipe() {
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateLayout() {
        if (this.gridView.getChildCount() <= 0) {
            return;
        }
        View child = this.gridView.getChildAt(0);
        RecyclerListView.Holder holder = (RecyclerListView.Holder) this.gridView.findContainingViewHolder(child);
        int top = child.getTop() - AndroidUtilities.dp(8.0f);
        int newOffset = (top <= 0 || holder == null || holder.getAdapterPosition() != 0) ? 0 : top;
        if (top >= 0 && holder != null && holder.getAdapterPosition() == 0) {
            newOffset = top;
            runShadowAnimation(0, false);
        } else {
            runShadowAnimation(0, true);
        }
        if (this.scrollOffsetY != newOffset) {
            RecyclerListView recyclerListView = this.gridView;
            this.scrollOffsetY = newOffset;
            recyclerListView.setTopGlowOffset(newOffset);
            this.frameLayout.setTranslationY(this.scrollOffsetY);
            this.searchEmptyView.setTranslationY(this.scrollOffsetY);
            this.containerView.invalidate();
        }
    }

    private void runShadowAnimation(final int num, final boolean show) {
        if ((show && this.shadow[num].getTag() != null) || (!show && this.shadow[num].getTag() == null)) {
            this.shadow[num].setTag(show ? null : 1);
            if (show) {
                this.shadow[num].setVisibility(0);
            }
            AnimatorSet[] animatorSetArr = this.shadowAnimation;
            if (animatorSetArr[num] != null) {
                animatorSetArr[num].cancel();
            }
            this.shadowAnimation[num] = new AnimatorSet();
            AnimatorSet animatorSet = this.shadowAnimation[num];
            Animator[] animatorArr = new Animator[1];
            View view = this.shadow[num];
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = show ? 1.0f : 0.0f;
            animatorArr[0] = ObjectAnimator.ofFloat(view, (Property<View, Float>) property, fArr);
            animatorSet.playTogether(animatorArr);
            this.shadowAnimation[num].setDuration(150L);
            this.shadowAnimation[num].addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ShareAlert.8
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (ShareAlert.this.shadowAnimation[num] != null && ShareAlert.this.shadowAnimation[num].equals(animation)) {
                        if (!show) {
                            ShareAlert.this.shadow[num].setVisibility(4);
                        }
                        ShareAlert.this.shadowAnimation[num] = null;
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (ShareAlert.this.shadowAnimation[num] != null && ShareAlert.this.shadowAnimation[num].equals(animation)) {
                        ShareAlert.this.shadowAnimation[num] = null;
                    }
                }
            });
            this.shadowAnimation[num].start();
        }
    }

    private void copyLink(Context context) {
        if (this.exportedMessageLink == null && this.linkToCopy == null) {
            return;
        }
        try {
            ClipboardManager clipboard = (ClipboardManager) ApplicationLoader.applicationContext.getSystemService("clipboard");
            ClipData clip = ClipData.newPlainText("label", this.linkToCopy != null ? this.linkToCopy : this.exportedMessageLink.link);
            clipboard.setPrimaryClip(clip);
            if (this.exportedMessageLink != null && this.exportedMessageLink.link.contains("/c/")) {
                ToastUtils.show(R.string.LinkCopiedPrivate);
            } else {
                ToastUtils.show(R.string.LinkCopied);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private boolean showCommentTextView(final boolean show) {
        if (show == (this.frameLayout2.getTag() != null)) {
            return false;
        }
        AnimatorSet animatorSet = this.animatorSet;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.frameLayout2.setTag(show ? 1 : null);
        if (this.commentTextView.getEditText().isFocused()) {
            AndroidUtilities.hideKeyboard(this.commentTextView.getEditText());
        }
        this.commentTextView.hidePopup(true);
        if (show) {
            this.frameLayout2.setVisibility(0);
            this.writeButtonContainer.setVisibility(0);
        }
        this.animatorSet = new AnimatorSet();
        ArrayList<Animator> animators = new ArrayList<>();
        FrameLayout frameLayout = this.frameLayout2;
        Property property = View.ALPHA;
        float[] fArr = new float[1];
        fArr[0] = show ? 1.0f : 0.0f;
        animators.add(ObjectAnimator.ofFloat(frameLayout, (Property<FrameLayout, Float>) property, fArr));
        FrameLayout frameLayout2 = this.writeButtonContainer;
        Property property2 = View.SCALE_X;
        float[] fArr2 = new float[1];
        fArr2[0] = show ? 1.0f : 0.2f;
        animators.add(ObjectAnimator.ofFloat(frameLayout2, (Property<FrameLayout, Float>) property2, fArr2));
        FrameLayout frameLayout3 = this.writeButtonContainer;
        Property property3 = View.SCALE_Y;
        float[] fArr3 = new float[1];
        fArr3[0] = show ? 1.0f : 0.2f;
        animators.add(ObjectAnimator.ofFloat(frameLayout3, (Property<FrameLayout, Float>) property3, fArr3));
        FrameLayout frameLayout4 = this.writeButtonContainer;
        Property property4 = View.ALPHA;
        float[] fArr4 = new float[1];
        fArr4[0] = show ? 1.0f : 0.0f;
        animators.add(ObjectAnimator.ofFloat(frameLayout4, (Property<FrameLayout, Float>) property4, fArr4));
        View view = this.selectedCountView;
        Property property5 = View.SCALE_X;
        float[] fArr5 = new float[1];
        fArr5[0] = show ? 1.0f : 0.2f;
        animators.add(ObjectAnimator.ofFloat(view, (Property<View, Float>) property5, fArr5));
        View view2 = this.selectedCountView;
        Property property6 = View.SCALE_Y;
        float[] fArr6 = new float[1];
        fArr6[0] = show ? 1.0f : 0.2f;
        animators.add(ObjectAnimator.ofFloat(view2, (Property<View, Float>) property6, fArr6));
        View view3 = this.selectedCountView;
        Property property7 = View.ALPHA;
        float[] fArr7 = new float[1];
        fArr7[0] = show ? 1.0f : 0.0f;
        animators.add(ObjectAnimator.ofFloat(view3, (Property<View, Float>) property7, fArr7));
        TextView textView = this.pickerBottomLayout;
        if (textView == null || textView.getVisibility() != 0) {
            View view4 = this.shadow[1];
            Property property8 = View.ALPHA;
            float[] fArr8 = new float[1];
            fArr8[0] = show ? 1.0f : 0.0f;
            animators.add(ObjectAnimator.ofFloat(view4, (Property<View, Float>) property8, fArr8));
        }
        this.animatorSet.playTogether(animators);
        this.animatorSet.setInterpolator(new DecelerateInterpolator());
        this.animatorSet.setDuration(180L);
        this.animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ShareAlert.9
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (animation.equals(ShareAlert.this.animatorSet)) {
                    if (!show) {
                        ShareAlert.this.frameLayout2.setVisibility(4);
                        ShareAlert.this.writeButtonContainer.setVisibility(4);
                    }
                    ShareAlert.this.animatorSet = null;
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (animation.equals(ShareAlert.this.animatorSet)) {
                    ShareAlert.this.animatorSet = null;
                }
            }
        });
        this.animatorSet.start();
        return true;
    }

    public void updateSelectedCount(int animated) {
        if (this.selectedDialogs.size() == 0) {
            this.selectedCountView.setPivotX(0.0f);
            this.selectedCountView.setPivotY(0.0f);
            showCommentTextView(false);
            return;
        }
        this.selectedCountView.invalidate();
        if (!showCommentTextView(true) && animated != 0) {
            this.selectedCountView.setPivotX(AndroidUtilities.dp(21.0f));
            this.selectedCountView.setPivotY(AndroidUtilities.dp(12.0f));
            AnimatorSet animatorSet = new AnimatorSet();
            Animator[] animatorArr = new Animator[2];
            View view = this.selectedCountView;
            Property property = View.SCALE_X;
            float[] fArr = new float[2];
            fArr[0] = animated == 1 ? 1.1f : 0.9f;
            fArr[1] = 1.0f;
            animatorArr[0] = ObjectAnimator.ofFloat(view, (Property<View, Float>) property, fArr);
            View view2 = this.selectedCountView;
            Property property2 = View.SCALE_Y;
            float[] fArr2 = new float[2];
            fArr2[0] = animated != 1 ? 0.9f : 1.1f;
            fArr2[1] = 1.0f;
            animatorArr[1] = ObjectAnimator.ofFloat(view2, (Property<View, Float>) property2, fArr2);
            animatorSet.playTogether(animatorArr);
            animatorSet.setInterpolator(new OvershootInterpolator());
            animatorSet.setDuration(180L);
            animatorSet.start();
            return;
        }
        this.selectedCountView.setPivotX(0.0f);
        this.selectedCountView.setPivotY(0.0f);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        EditTextEmoji editTextEmoji = this.commentTextView;
        if (editTextEmoji != null) {
            AndroidUtilities.hideKeyboard(editTextEmoji.getEditText());
        }
        super.dismiss();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.dialogsNeedReload);
    }

    private class ShareDialogsAdapter extends RecyclerListView.SelectionAdapter {
        private Context context;
        private int currentCount;
        private ArrayList<TLRPC.Dialog> dialogs = new ArrayList<>();
        private LongSparseArray<TLRPC.Dialog> dialogsMap = new LongSparseArray<>();

        public ShareDialogsAdapter(Context context) {
            this.context = context;
            fetchDialogs();
        }

        /* JADX WARN: Removed duplicated region for block: B:44:0x00e3  */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void fetchDialogs() {
            /*
                Method dump skipped, instruction units count: 324
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.ShareAlert.ShareDialogsAdapter.fetchDialogs():void");
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = this.dialogs.size();
            if (count != 0) {
                return count + 1;
            }
            return count;
        }

        public TLRPC.Dialog getItem(int position) {
            int position2 = position - 1;
            if (position2 < 0 || position2 >= this.dialogs.size()) {
                return null;
            }
            return this.dialogs.get(position2);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() != 1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new ShareDialogCell(this.context);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(100.0f)));
            } else {
                view = new View(this.context);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(56.0f)));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            if (holder.getItemViewType() == 0) {
                ShareDialogCell cell = (ShareDialogCell) holder.itemView;
                TLRPC.Dialog dialog = getItem(position);
                cell.setDialog((int) dialog.id, ShareAlert.this.selectedDialogs.indexOfKey(dialog.id) >= 0, null);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == 0) {
                return 1;
            }
            return 0;
        }
    }

    public class ShareSearchAdapter extends RecyclerListView.SelectionAdapter {
        private Context context;
        private int lastReqId;
        private int lastSearchId;
        private String lastSearchText;
        private int reqId;
        private ArrayList<DialogSearchResult> searchResult = new ArrayList<>();
        private Runnable searchRunnable;

        /* JADX INFO: Access modifiers changed from: private */
        class DialogSearchResult {
            public int date;
            public TLRPC.Dialog dialog;
            public CharSequence name;
            public TLObject object;

            private DialogSearchResult() {
                this.dialog = new TLRPC.TL_dialog();
            }
        }

        public ShareSearchAdapter(Context context) {
            this.context = context;
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* JADX INFO: renamed from: searchDialogsInternal, reason: merged with bridge method [inline-methods] */
        public void lambda$searchDialogs$3$ShareAlert$ShareSearchAdapter(final String query, final int searchId) {
            MessagesStorage.getInstance(ShareAlert.this.currentAccount).getStorageQueue().postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ShareAlert$ShareSearchAdapter$9r4QBgAJab7esy5-N9QTzM1stNw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$searchDialogsInternal$1$ShareAlert$ShareSearchAdapter(query, searchId);
                }
            });
        }

        /* JADX WARN: Removed duplicated region for block: B:182:0x049b A[Catch: Exception -> 0x04df, LOOP:7: B:151:0x03b9->B:182:0x049b, LOOP_END, TryCatch #0 {Exception -> 0x04df, blocks: (B:3:0x0002, B:5:0x0011, B:7:0x001e, B:9:0x002c, B:16:0x003a, B:18:0x0041, B:19:0x0043, B:20:0x0069, B:22:0x0070, B:26:0x0090, B:28:0x009a, B:29:0x00a2, B:31:0x00ad, B:33:0x00b9, B:36:0x00cc, B:37:0x00f4, B:39:0x00fa, B:42:0x010f, B:44:0x0117, B:45:0x011e, B:47:0x012b, B:49:0x0139, B:52:0x0152, B:54:0x0158, B:58:0x0170, B:65:0x0180, B:67:0x018b, B:69:0x01ab, B:73:0x01c0, B:75:0x01f2, B:74:0x01cb, B:77:0x020a, B:80:0x022c, B:82:0x0242, B:84:0x0248, B:85:0x026f, B:87:0x0275, B:91:0x028b, B:93:0x028e, B:95:0x0296, B:98:0x02ad, B:100:0x02b3, B:103:0x02c9, B:104:0x02cc, B:106:0x02d3, B:108:0x02e1, B:110:0x02e7, B:112:0x02ed, B:114:0x02f1, B:116:0x02f5, B:118:0x02fb, B:122:0x0306, B:128:0x0340, B:129:0x0343, B:130:0x0349, B:132:0x034f, B:134:0x0359, B:136:0x035d, B:137:0x0360, B:138:0x0363, B:139:0x037a, B:141:0x0380, B:144:0x038d, B:147:0x03a1, B:149:0x03ab, B:150:0x03b2, B:152:0x03bb, B:154:0x03c9, B:157:0x03e2, B:159:0x03e8, B:163:0x0400, B:170:0x0410, B:172:0x041b, B:174:0x0438, B:176:0x044a, B:178:0x0456, B:180:0x0489, B:179:0x0462, B:182:0x049b, B:185:0x04c9), top: B:195:0x0002 }] */
        /* JADX WARN: Removed duplicated region for block: B:209:0x0180 A[SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:232:0x0410 A[SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:77:0x020a A[Catch: Exception -> 0x04df, LOOP:2: B:46:0x0129->B:77:0x020a, LOOP_END, TryCatch #0 {Exception -> 0x04df, blocks: (B:3:0x0002, B:5:0x0011, B:7:0x001e, B:9:0x002c, B:16:0x003a, B:18:0x0041, B:19:0x0043, B:20:0x0069, B:22:0x0070, B:26:0x0090, B:28:0x009a, B:29:0x00a2, B:31:0x00ad, B:33:0x00b9, B:36:0x00cc, B:37:0x00f4, B:39:0x00fa, B:42:0x010f, B:44:0x0117, B:45:0x011e, B:47:0x012b, B:49:0x0139, B:52:0x0152, B:54:0x0158, B:58:0x0170, B:65:0x0180, B:67:0x018b, B:69:0x01ab, B:73:0x01c0, B:75:0x01f2, B:74:0x01cb, B:77:0x020a, B:80:0x022c, B:82:0x0242, B:84:0x0248, B:85:0x026f, B:87:0x0275, B:91:0x028b, B:93:0x028e, B:95:0x0296, B:98:0x02ad, B:100:0x02b3, B:103:0x02c9, B:104:0x02cc, B:106:0x02d3, B:108:0x02e1, B:110:0x02e7, B:112:0x02ed, B:114:0x02f1, B:116:0x02f5, B:118:0x02fb, B:122:0x0306, B:128:0x0340, B:129:0x0343, B:130:0x0349, B:132:0x034f, B:134:0x0359, B:136:0x035d, B:137:0x0360, B:138:0x0363, B:139:0x037a, B:141:0x0380, B:144:0x038d, B:147:0x03a1, B:149:0x03ab, B:150:0x03b2, B:152:0x03bb, B:154:0x03c9, B:157:0x03e2, B:159:0x03e8, B:163:0x0400, B:170:0x0410, B:172:0x041b, B:174:0x0438, B:176:0x044a, B:178:0x0456, B:180:0x0489, B:179:0x0462, B:182:0x049b, B:185:0x04c9), top: B:195:0x0002 }] */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public /* synthetic */ void lambda$searchDialogsInternal$1$ShareAlert$ShareSearchAdapter(java.lang.String r29, int r30) {
            /*
                Method dump skipped, instruction units count: 1254
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.ShareAlert.ShareSearchAdapter.lambda$searchDialogsInternal$1$ShareAlert$ShareSearchAdapter(java.lang.String, int):void");
        }

        static /* synthetic */ int lambda$null$0(DialogSearchResult lhs, DialogSearchResult rhs) {
            if (lhs.date < rhs.date) {
                return 1;
            }
            if (lhs.date > rhs.date) {
                return -1;
            }
            return 0;
        }

        private void updateSearchResults(final ArrayList<DialogSearchResult> result, final int searchId) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ShareAlert$ShareSearchAdapter$qdMw2x-rRwwQhZ0u53A70rEy9ac
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$updateSearchResults$2$ShareAlert$ShareSearchAdapter(searchId, result);
                }
            });
        }

        public /* synthetic */ void lambda$updateSearchResults$2$ShareAlert$ShareSearchAdapter(int searchId, ArrayList result) {
            if (searchId == this.lastSearchId) {
                if (ShareAlert.this.gridView.getAdapter() != ShareAlert.this.searchAdapter) {
                    ShareAlert shareAlert = ShareAlert.this;
                    shareAlert.topBeforeSwitch = shareAlert.getCurrentTop();
                    ShareAlert.this.gridView.setAdapter(ShareAlert.this.searchAdapter);
                    ShareAlert.this.searchAdapter.notifyDataSetChanged();
                }
                int a = 0;
                while (true) {
                    if (a >= result.size()) {
                        break;
                    }
                    DialogSearchResult obj = (DialogSearchResult) result.get(a);
                    if (obj.object instanceof TLRPC.User) {
                        TLRPC.User user = (TLRPC.User) obj.object;
                        MessagesController.getInstance(ShareAlert.this.currentAccount).putUser(user, true);
                    } else if (obj.object instanceof TLRPC.Chat) {
                        TLRPC.Chat chat = (TLRPC.Chat) obj.object;
                        MessagesController.getInstance(ShareAlert.this.currentAccount).putChat(chat, true);
                    }
                    a++;
                }
                boolean becomeEmpty = !this.searchResult.isEmpty() && result.isEmpty();
                boolean isEmpty = this.searchResult.isEmpty() && result.isEmpty();
                if (becomeEmpty) {
                    ShareAlert shareAlert2 = ShareAlert.this;
                    shareAlert2.topBeforeSwitch = shareAlert2.getCurrentTop();
                }
                this.searchResult = result;
                notifyDataSetChanged();
                if (!isEmpty && !becomeEmpty && ShareAlert.this.topBeforeSwitch > 0) {
                    ShareAlert.this.layoutManager.scrollToPositionWithOffset(0, -ShareAlert.this.topBeforeSwitch);
                    ShareAlert.this.topBeforeSwitch = -1000;
                }
                ShareAlert.this.searchEmptyView.showTextView();
            }
        }

        public void searchDialogs(final String query) {
            if (query != null && query.equals(this.lastSearchText)) {
                return;
            }
            this.lastSearchText = query;
            if (this.searchRunnable != null) {
                Utilities.searchQueue.cancelRunnable(this.searchRunnable);
                this.searchRunnable = null;
            }
            if (query == null || query.length() == 0) {
                this.searchResult.clear();
                ShareAlert shareAlert = ShareAlert.this;
                shareAlert.topBeforeSwitch = shareAlert.getCurrentTop();
                this.lastSearchId = -1;
                notifyDataSetChanged();
                return;
            }
            final int searchId = this.lastSearchId + 1;
            this.lastSearchId = searchId;
            this.searchRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ShareAlert$ShareSearchAdapter$YA_J6CZ-0sQBY_DRDerDB-WZeDA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$searchDialogs$3$ShareAlert$ShareSearchAdapter(query, searchId);
                }
            };
            Utilities.searchQueue.postRunnable(this.searchRunnable, 300L);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = this.searchResult.size();
            if (count != 0) {
                return count + 1;
            }
            return count;
        }

        public TLRPC.Dialog getItem(int position) {
            int position2 = position - 1;
            if (position2 < 0 || position2 >= this.searchResult.size()) {
                return null;
            }
            return this.searchResult.get(position2).dialog;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() != 1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = new ShareDialogCell(this.context);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(100.0f)));
            } else {
                view = new View(this.context);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(56.0f)));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            if (holder.getItemViewType() == 0) {
                ShareDialogCell cell = (ShareDialogCell) holder.itemView;
                DialogSearchResult result = this.searchResult.get(position - 1);
                cell.setDialog((int) result.dialog.id, ShareAlert.this.selectedDialogs.indexOfKey(result.dialog.id) >= 0, result.name);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == 0) {
                return 1;
            }
            return 0;
        }
    }
}
