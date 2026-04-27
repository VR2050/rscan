package im.uwrkaxlmjj.ui.dialogs;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.blankj.utilcode.util.ColorUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.wallet.cell.BankCardSelectCell;
import im.uwrkaxlmjj.ui.wallet.model.PayChannelBean;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletChannelAlert extends BottomSheet implements NotificationCenter.NotificationCenterDelegate {
    public static final int TYPE_TOP_UP = 1;
    public static final int TYPE_WITHDRAW = 0;
    private ListAdapter adapter;
    private ChannelAlertDelegate delegate;
    private LinearLayout emptyLayout;
    private LinearLayoutManager layoutManager;
    private RecyclerListView listView;
    private ImageView mIvBack;
    private ArrayList<PayChannelBean> modelList;
    BaseFragment parentFragment;
    PayChannelBean selectedCard;
    private TextView tvTitle;
    int type;

    public interface ChannelAlertDelegate {
        void onSelected(PayChannelBean payChannelBean);
    }

    public WalletChannelAlert(Context context) {
        super(context, false, 1);
        init(context);
    }

    public WalletChannelAlert(Context context, BaseFragment baseFragment, ArrayList<PayChannelBean> list, PayChannelBean selectedCard, int type, ChannelAlertDelegate bankCardAlertDelegate) {
        super(context, false, 1);
        this.parentFragment = baseFragment;
        this.delegate = bankCardAlertDelegate;
        this.modelList = list;
        this.selectedCard = selectedCard;
        this.type = type;
        init(context);
    }

    private void init(Context context) {
        View view = LayoutInflater.from(context).inflate(R.layout.wallet_channels_alert_layout, (ViewGroup) null);
        setCustomView(view);
        setCancelable(false);
        initView(context, view);
    }

    private void initView(Context context, View view) {
        setBackgroundColor(ColorUtils.getColor(R.color.window_background_gray));
        this.mIvBack = (ImageView) view.findViewById(R.attr.iv_back);
        this.tvTitle = (TextView) view.findViewById(R.attr.tv_title);
        this.emptyLayout = (LinearLayout) view.findViewById(R.attr.emptyLayout);
        this.listView = (RecyclerListView) view.findViewById(R.attr.listView);
        int i = this.type;
        if (i == 0) {
            this.tvTitle.setText(LocaleController.getString(R.string.WithdrawalChannel));
        } else if (i == 1) {
            this.tvTitle.setText(LocaleController.getString(R.string.TopUpChannel));
        } else {
            this.tvTitle.setText(LocaleController.getString(R.string.SelectPayWayTitle));
        }
        this.layoutManager = new LinearLayoutManager(getContext());
        this.adapter = new ListAdapter(context);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setTag(13);
        this.listView.setClipToPadding(false);
        this.listView.setGlowColor(Theme.getColor(Theme.key_dialogScrollGlow));
        this.listView.setEmptyView(this.emptyLayout);
        this.listView.setLayoutManager(this.layoutManager);
        this.listView.setAdapter(this.adapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.WalletChannelAlert.1
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public void onItemClick(View view2, int position) {
                if (WalletChannelAlert.this.modelList != null && WalletChannelAlert.this.delegate != null) {
                    WalletChannelAlert.this.dismiss();
                    WalletChannelAlert.this.delegate.onSelected((PayChannelBean) WalletChannelAlert.this.modelList.get(position));
                }
            }
        });
        this.mIvBack.setBackground(Theme.createSelectorDrawable(ColorUtils.getColor(R.color.click_selector)));
        this.mIvBack.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.dialogs.-$$Lambda$WalletChannelAlert$3QraafO2A3HB1YyQWbfTW9vL3t8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$initView$0$WalletChannelAlert(view2);
            }
        });
        this.adapter.notifyDataSetChanged();
    }

    public /* synthetic */ void lambda$initView$0$WalletChannelAlert(View v) {
        dismiss();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithSwipe() {
        return false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        super.dismiss();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;
        private int totalItems;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = new BankCardSelectCell(this.mContext);
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(70.0f)));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            BankCardSelectCell cell = (BankCardSelectCell) holder.itemView;
            PayChannelBean bean = (PayChannelBean) WalletChannelAlert.this.modelList.get(position);
            boolean checked = false;
            if (WalletChannelAlert.this.selectedCard != null) {
                String selectedPayType = WalletChannelAlert.this.selectedCard.getPayType().getPayType();
                String payType = bean.getPayType().getPayType();
                checked = payType.equals(selectedPayType);
            }
            cell.setText(bean.getPayType().getName(), checked);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return this.totalItems;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            this.totalItems = WalletChannelAlert.this.modelList != null ? WalletChannelAlert.this.modelList.size() : 0;
            super.notifyDataSetChanged();
        }
    }
}
