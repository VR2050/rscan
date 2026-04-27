package im.uwrkaxlmjj.ui.dialogs;

import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.recyclerview.widget.LinearScrollOffsetLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.recyclerview.OnItemClickListener;
import im.uwrkaxlmjj.ui.dialogs.WalletSelectAbsDialog;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hviews.MryFrameLayout;
import im.uwrkaxlmjj.ui.hviews.MryLinearLayout;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletSelectAbsDialog<T, D extends WalletSelectAbsDialog, VH extends PageHolder> extends BottomSheet {
    protected RecyclerListView.SelectionAdapter adapter;
    protected boolean allowToOverlayActionBar;
    protected MryRoundButton btnConfirm;
    protected MryLinearLayout containerAddButton;
    protected MryFrameLayout containerRv;
    protected List<T> data;
    protected ImageView ivClose;
    protected OnAddButtonClickListener<D> onAddButtonClickListener;
    protected OnConfirmClickListener<T, D> onConfrimClickListener;
    protected OnItemClickListener<T> onItemClickListener;
    protected int recyclerViewMaxHeight;
    protected RecyclerListView rv;
    protected boolean rvAutoHideWhenEmptyData;
    protected int selectPosition;
    protected boolean showAddBtnView;
    protected boolean showCloseView;
    protected boolean showConfirmBtnView;
    protected boolean showDragView;
    protected boolean showListSelectIcon;
    protected boolean showRv;
    protected boolean showSideBar;
    protected boolean showTitleView;
    protected View titleContainer;
    protected MryTextView tvAdd;
    protected MryTextView tvTitle;
    protected MryRoundButton viewDrag;

    public interface OnAddButtonClickListener<D extends WalletSelectAbsDialog> {
        void onAddButtonClick(D d);
    }

    public interface OnConfirmClickListener<T, D extends WalletSelectAbsDialog> {
        void onConfirm(D d, int i, T t);
    }

    public WalletSelectAbsDialog(Context context) {
        this(context, 1);
    }

    public WalletSelectAbsDialog(Context context, boolean useNestScrollViewAsParent) {
        this(context, 1, useNestScrollViewAsParent);
    }

    public WalletSelectAbsDialog(Context context, int backgroundType) {
        this(context, false, backgroundType, false);
    }

    public WalletSelectAbsDialog(Context context, int backgroundType, boolean useNestScrollViewAsParent) {
        this(context, false, backgroundType, useNestScrollViewAsParent);
    }

    public WalletSelectAbsDialog(Context context, boolean needFocus, int backgroundType, boolean useNestScrollViewAsParent) {
        super(context, needFocus, backgroundType);
        init(context, needFocus, backgroundType, useNestScrollViewAsParent);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected final void init(Context context, boolean needFocus, int backgroundType) {
    }

    protected void init(Context context, boolean needFocus, int backgroundType, boolean useNestScrollViewAsParent) {
        super.init(context, needFocus, backgroundType);
        setBackgroundColor(Theme.getColor(Theme.key_dialogBackgroundGray));
        setApplyTopPadding(false);
        setApplyBottomPadding(false);
        View view = LayoutInflater.from(context).inflate(R.layout.wallet_dialog_select_abs, (ViewGroup) null, false);
        setCustomView(view);
        initView(view, context);
    }

    protected void initView(View rootView, Context context) {
        this.showDragView = false;
        this.showTitleView = true;
        this.showCloseView = true;
        this.showRv = true;
        this.showSideBar = false;
        this.rvAutoHideWhenEmptyData = true;
        this.showAddBtnView = false;
        this.showConfirmBtnView = true;
        this.showListSelectIcon = true;
        this.viewDrag = (MryRoundButton) rootView.findViewById(R.attr.viewDrag);
        this.titleContainer = rootView.findViewById(R.attr.titleContainer);
        this.ivClose = (ImageView) rootView.findViewById(R.attr.ivClose);
        this.tvTitle = (MryTextView) rootView.findViewById(R.attr.tvTitle);
        this.containerRv = (MryFrameLayout) rootView.findViewById(R.attr.containerRv);
        this.containerAddButton = (MryLinearLayout) rootView.findViewById(R.attr.containerAddButton);
        this.tvAdd = (MryTextView) rootView.findViewById(R.attr.tvAdd);
        this.btnConfirm = (MryRoundButton) rootView.findViewById(R.attr.btnConfirm);
        this.containerRv.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        initRv(context);
        this.ivClose.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.-$$Lambda$WalletSelectAbsDialog$qU_iwRlC-h5O_16p7Zbi2PQcIrw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$0$WalletSelectAbsDialog(view);
            }
        });
        this.containerAddButton.setBackgroundColor(Theme.getColor(Theme.key_dialogBackground));
        this.containerAddButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.-$$Lambda$WalletSelectAbsDialog$wssO9lu9ub835RpOncRwSeiwm94
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$1$WalletSelectAbsDialog(view);
            }
        });
        this.btnConfirm.setPrimaryRadiusAdjustBoundsFillStyle();
        this.btnConfirm.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.-$$Lambda$WalletSelectAbsDialog$5Fj8AN3Nf2M7ASleRCvqHD2bkEc
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$2$WalletSelectAbsDialog(view);
            }
        });
    }

    public /* synthetic */ void lambda$initView$0$WalletSelectAbsDialog(View view1) {
        dismiss();
    }

    public /* synthetic */ void lambda$initView$1$WalletSelectAbsDialog(View v) {
        OnAddButtonClickListener<D> onAddButtonClickListener = this.onAddButtonClickListener;
        if (onAddButtonClickListener != null) {
            onAddButtonClickListener.onAddButtonClick(this);
        }
    }

    public /* synthetic */ void lambda$initView$2$WalletSelectAbsDialog(View view1) {
        OnConfirmClickListener<T, D> onConfirmClickListener = this.onConfrimClickListener;
        if (onConfirmClickListener != null) {
            int i = this.selectPosition;
            onConfirmClickListener.onConfirm(this, i, getItem(i));
        }
    }

    protected void initRv(Context context) {
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.dialogs.WalletSelectAbsDialog.1
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.View
            protected void onMeasure(int widthSpec, int heightSpec) {
                int h;
                super.onMeasure(widthSpec, heightSpec);
                int w = View.MeasureSpec.getSize(widthSpec);
                int height = getMeasuredHeight();
                int h2 = View.MeasureSpec.getSize(heightSpec);
                int maxh = (WalletSelectAbsDialog.this.applyTopPadding ? AndroidUtilities.dp(8.0f) : 0) + (WalletSelectAbsDialog.this.applyBottomPadding ? AndroidUtilities.dp(8.0f) : 0);
                if (!WalletSelectAbsDialog.this.allowToOverlayActionBar) {
                    maxh += ActionBar.getCurrentActionBarHeight();
                }
                if (WalletSelectAbsDialog.this.showDragView) {
                    maxh += AndroidUtilities.dp(20.0f);
                }
                if (WalletSelectAbsDialog.this.showTitleView) {
                    maxh += AndroidUtilities.dp(56.0f);
                }
                if (WalletSelectAbsDialog.this.showAddBtnView) {
                    maxh += AndroidUtilities.dp(88.0f);
                }
                if (WalletSelectAbsDialog.this.showConfirmBtnView) {
                    maxh += AndroidUtilities.dp(118.0f);
                }
                if (AndroidUtilities.displaySize.y > AndroidUtilities.displaySize.x) {
                    h = Math.min(h2, AndroidUtilities.displaySize.y - maxh);
                } else {
                    h = Math.min(h2, AndroidUtilities.displaySize.x - maxh);
                }
                int h3 = Math.min(h, height);
                if (h3 <= 0) {
                    h3 = AndroidUtilities.dp(250.0f);
                }
                if (WalletSelectAbsDialog.this.recyclerViewMaxHeight > 0) {
                    h3 = Math.min(WalletSelectAbsDialog.this.recyclerViewMaxHeight, h3);
                }
                setMeasuredDimension(w, h3);
            }
        };
        this.rv = recyclerListView;
        this.containerRv.addView(recyclerListView, 0, LayoutHelper.createFrame(-1, -2.0f));
        this.rv.setLayoutManager(new LinearScrollOffsetLayoutManager(context));
        this.rv.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.-$$Lambda$WalletSelectAbsDialog$3O3dxaRKio8IzHdtwmfG1ZQCJt0
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initRv$3$WalletSelectAbsDialog(view, i);
            }
        });
        RecyclerListView.SelectionAdapter selectionAdapter = new RecyclerListView.SelectionAdapter() { // from class: im.uwrkaxlmjj.ui.dialogs.WalletSelectAbsDialog.2
            /* JADX WARN: Multi-variable type inference failed */
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
            public boolean isEnabled(RecyclerView.ViewHolder holder) {
                return WalletSelectAbsDialog.this.isEnabled((PageHolder) holder);
            }

            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
                return WalletSelectAbsDialog.this.onCreateViewHolder(parent, viewType);
            }

            /* JADX WARN: Multi-variable type inference failed */
            /* JADX WARN: Type inference fix 'apply assigned field type' failed
            java.lang.UnsupportedOperationException: ArgType.getObject(), call class: class jadx.core.dex.instructions.args.ArgType$PrimitiveArg
            	at jadx.core.dex.instructions.args.ArgType.getObject(ArgType.java:593)
            	at jadx.core.dex.attributes.nodes.ClassTypeVarsAttr.getTypeVarsMapFor(ClassTypeVarsAttr.java:35)
            	at jadx.core.dex.nodes.utils.TypeUtils.replaceClassGenerics(TypeUtils.java:177)
            	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.insertExplicitUseCast(FixTypesVisitor.java:397)
            	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.tryFieldTypeWithNewCasts(FixTypesVisitor.java:359)
            	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.applyFieldType(FixTypesVisitor.java:309)
            	at jadx.core.dex.visitors.typeinference.FixTypesVisitor.visit(FixTypesVisitor.java:94)
             */
            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
                WalletSelectAbsDialog walletSelectAbsDialog = WalletSelectAbsDialog.this;
                walletSelectAbsDialog.onBindViewHolder(this, (PageHolder) holder, position, walletSelectAbsDialog.getItem(position));
            }

            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public int getItemCount() {
                return WalletSelectAbsDialog.this.getItemCount();
            }

            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public int getItemViewType(int position) {
                return WalletSelectAbsDialog.this.getItemViewType(position);
            }
        };
        this.adapter = selectionAdapter;
        this.rv.setAdapter(selectionAdapter);
    }

    public /* synthetic */ void lambda$initRv$3$WalletSelectAbsDialog(View view12, int position) {
        this.selectPosition = position;
        RecyclerListView.SelectionAdapter selectionAdapter = this.adapter;
        if (selectionAdapter != null) {
            selectionAdapter.notifyDataSetChanged();
        }
        dismiss();
        OnItemClickListener<T> onItemClickListener = this.onItemClickListener;
        if (onItemClickListener != null) {
            onItemClickListener.onItemClick(view12, position, getItem(position));
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet, android.app.Dialog
    protected void onCreate(Bundle savedInstanceState) {
        RecyclerListView.SelectionAdapter selectionAdapter;
        super.onCreate(savedInstanceState);
        if (this.containerView != null) {
            this.containerView.setClipToPadding(false);
        }
        MryRoundButton mryRoundButton = this.viewDrag;
        if (mryRoundButton != null) {
            if (this.showDragView && mryRoundButton.getVisibility() != 0) {
                this.viewDrag.setVisibility(0);
            } else if (!this.showDragView && this.viewDrag.getVisibility() != 8) {
                this.viewDrag.setVisibility(8);
            }
        }
        View view = this.titleContainer;
        if (view != null && this.tvTitle != null) {
            if (this.showTitleView && view.getVisibility() != 0) {
                this.titleContainer.setVisibility(0);
            } else if (!this.showTitleView && this.titleContainer.getVisibility() != 8) {
                this.titleContainer.setVisibility(8);
            }
        }
        View view2 = this.titleContainer;
        if (view2 != null && this.ivClose != null) {
            if (this.showCloseView && view2.getVisibility() != 0) {
                this.titleContainer.setVisibility(0);
            } else if (!this.showCloseView && this.titleContainer.getVisibility() != 8) {
                this.titleContainer.setVisibility(8);
            }
        }
        MryFrameLayout mryFrameLayout = this.containerRv;
        if (mryFrameLayout != null) {
            if (this.showRv) {
                if (this.rvAutoHideWhenEmptyData && (((selectionAdapter = this.adapter) == null || selectionAdapter.getItemCount() == 0) && this.containerRv.getVisibility() != 8)) {
                    this.containerRv.setVisibility(8);
                } else if (this.containerRv.getVisibility() != 0) {
                    this.containerRv.setVisibility(0);
                }
            } else if (mryFrameLayout.getVisibility() != 8) {
                this.containerRv.setVisibility(8);
            }
        }
        MryLinearLayout mryLinearLayout = this.containerAddButton;
        if (mryLinearLayout != null) {
            if (this.showAddBtnView && mryLinearLayout.getVisibility() != 0) {
                this.containerAddButton.setVisibility(0);
            } else if (!this.showAddBtnView && this.containerAddButton.getVisibility() != 8) {
                this.containerAddButton.setVisibility(8);
            }
        }
        MryRoundButton mryRoundButton2 = this.btnConfirm;
        if (mryRoundButton2 != null) {
            if (this.showConfirmBtnView && mryRoundButton2.getVisibility() != 0) {
                this.btnConfirm.setVisibility(0);
            } else if (!this.showConfirmBtnView && this.btnConfirm.getVisibility() != 8) {
                this.btnConfirm.setVisibility(8);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet, android.app.Dialog
    public void setTitle(CharSequence value) {
        boolean z = !TextUtils.isEmpty(value);
        this.showTitleView = z;
        MryTextView mryTextView = this.tvTitle;
        if (mryTextView != null && z) {
            mryTextView.setText(value);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithSwipe() {
        return false;
    }

    public boolean isEnabled(VH holder) {
        return false;
    }

    public VH onCreateViewHolder(ViewGroup parent, int viewType) {
        return null;
    }

    public void onBindViewHolder(RecyclerListView.SelectionAdapter adapter, VH holder, int position, T item) {
        boolean z = true;
        holder.setGone(R.attr.divider, position == getItemCount() - 1 && getItemCount() > 3);
        if (position == this.selectPosition && !this.showListSelectIcon) {
            z = false;
        }
        holder.setInVisible(R.attr.ivSelect, z);
        holder.setImageColorFilter(R.attr.ivSelect, Theme.key_windowBackgroundWhiteBlueButton);
    }

    public int getItemViewType(int position) {
        return 0;
    }

    public int getItemCount() {
        List<T> list = this.data;
        if (list != null) {
            return list.size();
        }
        return 0;
    }

    public int getSelectPosition() {
        return this.selectPosition;
    }

    public T getItem(int position) {
        List<T> list = this.data;
        if (list == null || position < 0 || position >= list.size()) {
            return null;
        }
        return this.data.get(position);
    }

    public List<T> getData() {
        return this.data;
    }

    public D setTitles(CharSequence titles) {
        setTitle(titles);
        return this;
    }

    public D setAdapter(RecyclerListView.SelectionAdapter adapter) {
        if (this.adapter != adapter) {
            this.adapter = adapter;
            RecyclerListView recyclerListView = this.rv;
            if (recyclerListView != null) {
                recyclerListView.setAdapter(adapter);
            }
        }
        return this;
    }

    public D setData(List<T> data) {
        this.data = data;
        return this;
    }

    public D setSelectPosition(int selectPosition) {
        this.selectPosition = selectPosition;
        return this;
    }

    public D setShowDragView(boolean showDragView) {
        this.showDragView = showDragView;
        if (showDragView) {
            setRecyclerViewContainerMargins(0, 20, 0, 0);
        }
        return this;
    }

    public D setShowTitleView(boolean showTitleView) {
        this.showTitleView = showTitleView;
        return this;
    }

    public D setShowCloseView(boolean showCloseView) {
        this.showCloseView = showCloseView;
        return this;
    }

    public D setShowRecyclerView(boolean showRv) {
        this.showRv = showRv;
        return this;
    }

    public D setShowSideBar(boolean showSideBar) {
        this.showSideBar = showSideBar;
        return this;
    }

    public D setShowAddButtonView(boolean showAddBtnView) {
        this.showAddBtnView = showAddBtnView;
        return this;
    }

    public D setShowConfirmButtonView(boolean showConfirmBtnView) {
        this.showConfirmBtnView = showConfirmBtnView;
        return this;
    }

    public D setShowListSelectIcon(boolean showListSelectIcon) {
        this.showListSelectIcon = showListSelectIcon;
        return this;
    }

    public D setRecyclerViewMinHeight(int recyclerViewMinHeight) {
        RecyclerListView recyclerListView = this.rv;
        if (recyclerListView != null) {
            recyclerListView.setMinimumHeight(recyclerViewMinHeight);
        }
        return this;
    }

    public D setRecyclerViewMaxHeight(int recyclerViewMaxHeight) {
        this.recyclerViewMaxHeight = recyclerViewMaxHeight;
        return this;
    }

    public D setRecyclerViewMargins(int i) {
        return (D) setRecyclerViewMargins(i, i, i, i);
    }

    public D setRecyclerViewMargins(int i, int i2, int i3, int i4) {
        return (D) setRecyclerViewMargins(i, i2, i3, i4, true);
    }

    public D setRecyclerViewMargins(int leftMargin, int topMargin, int rightMargin, int bottomMargin, boolean isDpValue) {
        RecyclerListView recyclerListView = this.rv;
        if (recyclerListView != null) {
            FrameLayout.LayoutParams lp = (FrameLayout.LayoutParams) recyclerListView.getLayoutParams();
            lp.leftMargin = isDpValue ? AndroidUtilities.dp(leftMargin) : leftMargin;
            lp.topMargin = isDpValue ? AndroidUtilities.dp(topMargin) : topMargin;
            lp.rightMargin = isDpValue ? AndroidUtilities.dp(rightMargin) : rightMargin;
            lp.bottomMargin = isDpValue ? AndroidUtilities.dp(bottomMargin) : bottomMargin;
            this.rv.setLayoutParams(lp);
        }
        return this;
    }

    public D setRecyclerViewContainerMargins(int i) {
        return (D) setRecyclerViewContainerMargins(i, i, i, i, true);
    }

    public D setRecyclerViewContainerMargins(int i, int i2, int i3, int i4) {
        return (D) setRecyclerViewContainerMargins(i, i2, i3, i4, true);
    }

    public D setRecyclerViewContainerMargins(int leftMargin, int topMargin, int rightMargin, int bottomMargin, boolean isDpValue) {
        MryFrameLayout mryFrameLayout = this.containerRv;
        if (mryFrameLayout != null) {
            LinearLayout.LayoutParams lp = (LinearLayout.LayoutParams) mryFrameLayout.getLayoutParams();
            lp.leftMargin = isDpValue ? AndroidUtilities.dp(leftMargin) : leftMargin;
            lp.topMargin = isDpValue ? AndroidUtilities.dp(topMargin) : topMargin;
            lp.rightMargin = isDpValue ? AndroidUtilities.dp(rightMargin) : rightMargin;
            lp.bottomMargin = isDpValue ? AndroidUtilities.dp(bottomMargin) : bottomMargin;
            this.containerRv.setLayoutParams(lp);
        }
        return this;
    }

    public D setRvAutoHideWhenEmptyData(boolean rvAutoHideWhenEmptyData) {
        this.rvAutoHideWhenEmptyData = rvAutoHideWhenEmptyData;
        return this;
    }

    public D setOnItemClickListener(OnItemClickListener<T> onItemClickListener) {
        this.onItemClickListener = onItemClickListener;
        return this;
    }

    public D setOnConfrimClickListener(OnConfirmClickListener<T, D> onConfrimClickListener) {
        this.onConfrimClickListener = onConfrimClickListener;
        return this;
    }

    public D setOnAddButtonClickListener(OnAddButtonClickListener<D> onAddButtonClickListener) {
        this.onAddButtonClickListener = onAddButtonClickListener;
        return this;
    }

    public MryRoundButton getDragView() {
        return this.viewDrag;
    }

    public View getTitleContainerView() {
        return this.titleContainer;
    }

    public ImageView getCloseView() {
        return this.ivClose;
    }

    public MryTextView getTitleTextView() {
        return this.tvTitle;
    }

    public MryFrameLayout getRecyclerViewContainerView() {
        return this.containerRv;
    }

    public RecyclerListView getRecyclerView() {
        return this.rv;
    }

    public MryLinearLayout getAddButtonContainerView() {
        return this.containerAddButton;
    }

    public MryTextView getAddButtonTextView() {
        return this.tvAdd;
    }

    public MryRoundButton getConfirmButton() {
        return this.btnConfirm;
    }

    public void destroy() {
        if (this.containerView != null) {
            this.containerView.removeAllViews();
        }
        if (this.container != null) {
            this.container.removeAllViews();
        }
        MryFrameLayout mryFrameLayout = this.containerRv;
        if (mryFrameLayout != null) {
            mryFrameLayout.removeAllViews();
        }
        RecyclerListView recyclerListView = this.rv;
        if (recyclerListView != null) {
            recyclerListView.setLayoutManager(null);
            this.rv.setAdapter(null);
            this.rv.setOnScrollListener(null);
        }
        MryLinearLayout mryLinearLayout = this.containerAddButton;
        if (mryLinearLayout != null) {
            mryLinearLayout.removeAllViews();
        }
        this.titleContainer = null;
        this.ivClose = null;
        this.tvTitle = null;
        this.containerRv = null;
        this.rv = null;
        this.containerAddButton = null;
        this.tvAdd = null;
        this.btnConfirm = null;
        this.adapter = null;
        this.data = null;
        this.onItemClickListener = null;
        this.onConfrimClickListener = null;
        this.onAddButtonClickListener = null;
        this.selectPosition = 0;
        this.recyclerViewMaxHeight = 0;
    }
}
