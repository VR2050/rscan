package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.core.view.ViewCompat;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.constants.ChatEnterMenuType;
import im.uwrkaxlmjj.ui.hviews.MryAlphaImageView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.page.PagerGridLayoutManager;
import im.uwrkaxlmjj.ui.hviews.page.PagerGridSnapHelper;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class EnterMenuView extends FrameLayout {
    private EnterMenuIndicator bottomPagesView;
    private TLRPC.Chat chatInfo;
    private int currentPage;
    private EnterMenuViewDelegate delegate;
    private Adapter mAdapter;
    private int mCurrentHeight;
    private PagerGridLayoutManager mLayoutManager;
    private RecyclerView mRv;

    public interface EnterMenuViewDelegate {
        void onItemClie(int i, ChatEnterMenuType chatEnterMenuType);
    }

    public EnterMenuView(Context context) {
        this(context, null);
    }

    public EnterMenuView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public EnterMenuView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
        RecyclerView recyclerView = new RecyclerView(getContext());
        this.mRv = recyclerView;
        addView(recyclerView, LayoutHelper.createFrame(-1, -1, 17));
        this.mRv.setPadding(0, AndroidUtilities.dp(16.0f), 0, AndroidUtilities.dp(16.0f));
        this.mRv.setOverScrollMode(2);
        PagerGridSnapHelper pageSnapHelper = new PagerGridSnapHelper();
        pageSnapHelper.attachToRecyclerView(this.mRv);
        this.mAdapter = new Adapter();
    }

    private void checkLayoutManager(boolean forceCreateNewLayoutManager) {
        if (forceCreateNewLayoutManager || this.mLayoutManager == null || this.mRv.getLayoutManager() == null) {
            PagerGridLayoutManager pagerGridLayoutManager = new PagerGridLayoutManager(2, 4, 1);
            this.mLayoutManager = pagerGridLayoutManager;
            pagerGridLayoutManager.setPageListener(new PagerGridLayoutManager.PageListener() { // from class: im.uwrkaxlmjj.ui.components.EnterMenuView.1
                @Override // im.uwrkaxlmjj.ui.hviews.page.PagerGridLayoutManager.PageListener
                public void onPageSizeChanged(int pageSize) {
                }

                @Override // im.uwrkaxlmjj.ui.hviews.page.PagerGridLayoutManager.PageListener
                public void onPageSelect(int pageIndex) {
                    EnterMenuView.this.currentPage = pageIndex;
                    if (EnterMenuView.this.bottomPagesView != null) {
                        EnterMenuView.this.bottomPagesView.setCurrentPage(pageIndex);
                    }
                }
            });
            this.mRv.setLayoutManager(this.mLayoutManager);
        }
    }

    private void checkPageBottomIndicator() {
        int total = this.mLayoutManager.getTotalPageCount();
        if (total > 1) {
            EnterMenuIndicator enterMenuIndicator = this.bottomPagesView;
            if (enterMenuIndicator == null) {
                EnterMenuIndicator enterMenuIndicator2 = new EnterMenuIndicator(getContext(), total);
                this.bottomPagesView = enterMenuIndicator2;
                addView(enterMenuIndicator2, LayoutHelper.createFrame(total * 11, 5.0f, 81, 0.0f, 0.0f, 0.0f, 16.0f));
                return;
            }
            enterMenuIndicator.setPagesCount(total);
        }
    }

    private void update(boolean forceCreateNewAdapter) {
        checkLayoutManager(forceCreateNewAdapter);
        if (forceCreateNewAdapter) {
            Adapter oldAdapter = this.mAdapter;
            Adapter adapter = new Adapter();
            this.mAdapter = adapter;
            adapter.setData(oldAdapter.attachTexts, oldAdapter.attachIcons, oldAdapter.attachTypes);
            this.mAdapter.setCurrentChat(this.chatInfo);
            this.mAdapter.setDelegate(this.delegate);
            this.mRv.setAdapter(this.mAdapter);
        } else if (this.mRv.getAdapter() == null) {
            this.mRv.setAdapter(this.mAdapter);
        } else {
            this.mAdapter.notifyDataSetChanged();
        }
        checkPageBottomIndicator();
    }

    @Override // android.view.View
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        if (this.mCurrentHeight != h) {
            this.mCurrentHeight = h;
            this.mRv.setOnFlingListener(null);
            update(true);
        }
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        if (this.currentPage != 0 && getParent() != null) {
            getParent().requestDisallowInterceptTouchEvent(true);
        }
        return super.onInterceptTouchEvent(ev);
    }

    @Override // android.view.View
    protected void onConfigurationChanged(Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
    }

    public void setDelegate(EnterMenuViewDelegate delegate) {
        this.delegate = delegate;
        Adapter adapter = this.mAdapter;
        if (adapter != null) {
            adapter.setDelegate(delegate);
        }
    }

    public void setCurrentChat(TLRPC.Chat chatInfo) {
        this.chatInfo = chatInfo;
        Adapter adapter = this.mAdapter;
        if (adapter == null) {
            return;
        }
        adapter.setCurrentChat(chatInfo);
        update(false);
    }

    public void setDataAndNotify(ArrayList<String> attachTexts, ArrayList<Integer> attachIcons, ArrayList<ChatEnterMenuType> attachTypes) {
        this.mAdapter.setData(attachTexts, attachIcons, attachTypes);
        update(false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class Adapter extends RecyclerView.Adapter<PageGridViewHolder> {
        ArrayList<Integer> attachIcons;
        ArrayList<String> attachTexts;
        ArrayList<ChatEnterMenuType> attachTypes;
        private TLRPC.Chat chatInfo;
        private EnterMenuViewDelegate delegate;

        private Adapter() {
            this.attachTexts = new ArrayList<>();
            this.attachIcons = new ArrayList<>();
            this.attachTypes = new ArrayList<>();
        }

        void setData(ArrayList<String> attachTexts, ArrayList<Integer> attachIcons, ArrayList<ChatEnterMenuType> attachTypes) {
            this.attachTexts = attachTexts;
            this.attachIcons = attachIcons;
            this.attachTypes = attachTypes;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void setCurrentChat(TLRPC.Chat chatInfo) {
            this.chatInfo = chatInfo;
        }

        public void setDelegate(EnterMenuViewDelegate delegate) {
            this.delegate = delegate;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public PageGridViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            LayoutInflater inflater = LayoutInflater.from(parent.getContext());
            View view = inflater.inflate(R.layout.item_attach_menu, parent, false);
            RecyclerView.LayoutParams layoutParams = new RecyclerView.LayoutParams(parent.getMeasuredWidth() / 4, parent.getMeasuredHeight() / 2);
            view.setLayoutParams(layoutParams);
            return new PageGridViewHolder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(PageGridViewHolder holder, final int position) {
            String title = this.attachTexts.get(position);
            holder.tvAttachText.setText(title);
            holder.ivAttachImage.setImageResource(this.attachIcons.get(position).intValue());
            if (Theme.getCurrentTheme() != null && Theme.getCurrentTheme().isDark()) {
                int color = Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton);
                holder.ivAttachImage.setColorFilter(new PorterDuffColorFilter(AndroidUtilities.alphaColor(0.4f, color), PorterDuff.Mode.MULTIPLY));
                holder.tvAttachText.setTextColor(AndroidUtilities.alphaColor(0.6f, color));
            } else {
                holder.tvAttachText.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
            }
            boolean enable = menuItemEnable(getItemMenuType(position));
            holder.itemView.setEnabled(enable);
            holder.ivAttachImage.setEnabled(enable);
            holder.tvAttachText.setEnabled(enable);
            holder.itemView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$EnterMenuView$Adapter$Rp5vcGFFmyxqkse_1HscYc3bZEM
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$onBindViewHolder$0$EnterMenuView$Adapter(position, view);
                }
            });
        }

        public /* synthetic */ void lambda$onBindViewHolder$0$EnterMenuView$Adapter(int position, View v) {
            EnterMenuViewDelegate enterMenuViewDelegate = this.delegate;
            if (enterMenuViewDelegate != null) {
                enterMenuViewDelegate.onItemClie(position, getItemMenuType(position));
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            ArrayList<String> arrayList = this.attachTexts;
            if (arrayList == null) {
                return 0;
            }
            return arrayList.size();
        }

        public ChatEnterMenuType getItemMenuType(int position) {
            ArrayList<ChatEnterMenuType> arrayList = this.attachTypes;
            if (arrayList == null || position < 0 || position >= arrayList.size()) {
                return null;
            }
            return this.attachTypes.get(position);
        }

        public boolean menuItemEnable(ChatEnterMenuType menuType) {
            TLRPC.Chat chat = this.chatInfo;
            if (chat == null) {
                return true;
            }
            if (!ChatObject.isChannel(chat) && !this.chatInfo.megagroup) {
                return true;
            }
            int i = AnonymousClass2.$SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType[menuType.ordinal()];
            if (i != 1 && i != 2 && i != 3 && i != 4) {
                return true;
            }
            if ((ChatObject.hasAdminRights(this.chatInfo) || this.chatInfo.default_banned_rights == null || !this.chatInfo.default_banned_rights.send_media) && ChatObject.canSendMedia(this.chatInfo)) {
                return true;
            }
            return false;
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.EnterMenuView$2, reason: invalid class name */
    static /* synthetic */ class AnonymousClass2 {
        static final /* synthetic */ int[] $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType;

        static {
            int[] iArr = new int[ChatEnterMenuType.values().length];
            $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType = iArr;
            try {
                iArr[ChatEnterMenuType.ALBUM.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType[ChatEnterMenuType.DOCUMENT.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType[ChatEnterMenuType.CAMERA.ordinal()] = 3;
            } catch (NoSuchFieldError e3) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType[ChatEnterMenuType.MUSIC.ordinal()] = 4;
            } catch (NoSuchFieldError e4) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType[ChatEnterMenuType.VOICECALL.ordinal()] = 5;
            } catch (NoSuchFieldError e5) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType[ChatEnterMenuType.VIDEOCALL.ordinal()] = 6;
            } catch (NoSuchFieldError e6) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType[ChatEnterMenuType.LOCATION.ordinal()] = 7;
            } catch (NoSuchFieldError e7) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType[ChatEnterMenuType.CONTACTS.ordinal()] = 8;
            } catch (NoSuchFieldError e8) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType[ChatEnterMenuType.TRANSFER.ordinal()] = 9;
            } catch (NoSuchFieldError e9) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType[ChatEnterMenuType.REDPACKET.ordinal()] = 10;
            } catch (NoSuchFieldError e10) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType[ChatEnterMenuType.FAVORITE.ordinal()] = 11;
            } catch (NoSuchFieldError e11) {
            }
            try {
                $SwitchMap$im$uwrkaxlmjj$ui$constants$ChatEnterMenuType[ChatEnterMenuType.POLL.ordinal()] = 12;
            } catch (NoSuchFieldError e12) {
            }
        }
    }

    public static class PageGridViewHolder extends RecyclerView.ViewHolder {
        public MryAlphaImageView ivAttachImage;
        public MryTextView tvAttachText;

        public PageGridViewHolder(View itemView) {
            super(itemView);
            this.tvAttachText = (MryTextView) itemView.findViewById(R.attr.tvAttachText);
            this.ivAttachImage = (MryAlphaImageView) itemView.findViewById(R.attr.ivAttachImage);
        }
    }

    public class SpaceItemDecoration extends RecyclerView.ItemDecoration {
        private int space;

        public SpaceItemDecoration(int space) {
            this.space = space;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
        public void getItemOffsets(android.graphics.Rect outRect, View view, RecyclerView parent, RecyclerView.State state) {
            outRect.top = this.space;
            outRect.bottom = this.space;
            outRect.left = this.space;
            outRect.right = this.space;
        }
    }

    public static class EnterMenuIndicator extends View {
        private int color;
        private int currentPage;
        private int pagesCount;
        private Paint paint;
        private RectF rect;
        private int scrollPosition;
        private int selectedColor;

        public EnterMenuIndicator(Context context, int count) {
            super(context);
            this.paint = new Paint(1);
            this.rect = new RectF();
            this.pagesCount = count;
        }

        public void setPagesCount(int pagesCount) {
            this.pagesCount = pagesCount;
            invalidate();
        }

        public void setPageOffset(int position, float offset) {
            this.scrollPosition = position;
            invalidate();
        }

        public void setCurrentPage(int page) {
            this.currentPage = page;
            invalidate();
        }

        public void setColor(String key, String selectedKey) {
            setColor(Theme.getColor(key), Theme.getColor(selectedKey));
        }

        public void setColor(int color, int selectedColor) {
            this.color = color;
            this.selectedColor = selectedColor;
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            int i = this.color;
            if (i != 0) {
                this.paint.setColor((i & ViewCompat.MEASURED_SIZE_MASK) | (-1275068416));
            } else {
                this.paint.setColor(Theme.getColor(Theme.key_actionBarDefaultSubmenuItemIcon));
            }
            for (int a = 0; a < this.pagesCount; a++) {
                if (a != this.currentPage) {
                    int x = AndroidUtilities.dp(11.0f) * a;
                    this.rect.set(x, 0.0f, AndroidUtilities.dp(5.0f) + x, AndroidUtilities.dp(5.0f));
                    canvas.drawRoundRect(this.rect, AndroidUtilities.dp(2.5f), AndroidUtilities.dp(2.5f), this.paint);
                }
            }
            int a2 = this.selectedColor;
            if (a2 != 0) {
                this.paint.setColor(a2);
            } else {
                this.paint.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            }
            int x2 = this.currentPage * AndroidUtilities.dp(11.0f);
            this.rect.set(x2, 0.0f, AndroidUtilities.dp(5.0f) + x2, AndroidUtilities.dp(5.0f));
            canvas.drawRoundRect(this.rect, AndroidUtilities.dp(2.5f), AndroidUtilities.dp(2.5f), this.paint);
        }
    }
}
