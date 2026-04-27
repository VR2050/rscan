package im.uwrkaxlmjj.ui.hui.discoveryweb;

import android.app.Activity;
import android.app.Dialog;
import android.view.Display;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.DividerCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hviews.MryAlphaLinearLayout;
import im.uwrkaxlmjj.ui.hviews.MryLinearLayout;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class DiscoveryJumpMenuDialog extends Dialog {
    private RecyclerListView rv;

    public DiscoveryJumpMenuDialog(Activity context) {
        super(context, R.plurals.DialogStyleBottomInAndOut);
        init(context);
    }

    private void init(final Activity context) {
        MryLinearLayout rootView = new MryLinearLayout(context);
        rootView.setBackgroundColor(Theme.getColor(Theme.key_dialogBackgroundGray));
        rootView.setRadius(AndroidUtilities.dp(10.0f), 3);
        setContentView(rootView, new ViewGroup.LayoutParams(-1, -2));
        WindowManager m = context.getWindowManager();
        Display d = m.getDefaultDisplay();
        Window window = getWindow();
        int width = 0;
        if (window != null) {
            WindowManager.LayoutParams lp = window.getAttributes();
            window.setGravity(80);
            lp.width = d.getWidth();
            width = lp.width;
            lp.dimAmount = 0.5f;
            window.setAttributes(lp);
        }
        setCancelable(true);
        rootView.setOrientation(1);
        LinearLayout llGameInfo = new LinearLayout(context);
        llGameInfo.setOrientation(0);
        rootView.addView(llGameInfo, LayoutHelper.createLinear(-1, 55));
        DividerCell divider = new DividerCell(context);
        rootView.addView(divider, LayoutHelper.createLinear(-1.0f, 0.5f));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.rv = recyclerListView;
        recyclerListView.setMinimumHeight(AndroidUtilities.dp(143.0f));
        rootView.addView(this.rv, new LinearLayout.LayoutParams(width, -2));
        this.rv.setLayoutManager(new GridLayoutManager(context, 4));
        RecyclerListView.SelectionAdapter adapter = new RecyclerListView.SelectionAdapter() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.DiscoveryJumpMenuDialog.1
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
            public boolean isEnabled(RecyclerView.ViewHolder holder) {
                return true;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
                MryAlphaLinearLayout ll = new MryAlphaLinearLayout(context);
                ll.setPadding(0, 0, 0, AndroidUtilities.dp(10.0f));
                ll.setOrientation(1);
                ImageView iv = new ImageView(context);
                iv.setTag(Integer.valueOf(Holder.TAG_IV));
                ll.addView(iv, LayoutHelper.createLinear(-1, -2, 1));
                MryTextView tv = new MryTextView(context);
                tv.setTextSize(0, AndroidUtilities.sp2px(12.0f));
                tv.setTag(Integer.valueOf(Holder.TAG_TV));
                tv.setTextColor(Theme.key_windowBackgroundWhiteGrayText3);
                ll.addView(tv, LayoutHelper.createLinear(-2, -2, 1));
                return new Holder(ll);
            }

            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public void onBindViewHolder(RecyclerView.ViewHolder holder1, int position) {
                String text;
                int resId;
                Holder holder = (Holder) holder1;
                if (position == 0) {
                    text = LocaleController.getString(R.string.Fold);
                    resId = R.id.ic_folder;
                } else {
                    text = LocaleController.getString(R.string.Refresh);
                    resId = R.id.ic_refresh;
                }
                holder.iv.setImageResource(resId);
                holder.tv.setText(text);
            }

            @Override // androidx.recyclerview.widget.RecyclerView.Adapter
            public int getItemCount() {
                return 2;
            }
        };
        this.rv.setAdapter(adapter);
        MryTextView btnCancel = new MryTextView(context);
        btnCancel.setGravity(17);
        btnCancel.setTextSize(0, AndroidUtilities.sp2px(15.0f));
        btnCancel.setText(LocaleController.getString(R.string.Cancel));
        btnCancel.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        btnCancel.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.-$$Lambda$DiscoveryJumpMenuDialog$UtUaGiLzISyI1sYvVg2JD-lYYhU
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$init$0$DiscoveryJumpMenuDialog(view);
            }
        });
        rootView.addView(btnCancel, LayoutHelper.createLinear(-1, 50));
    }

    public /* synthetic */ void lambda$init$0$DiscoveryJumpMenuDialog(View v) {
        dismiss();
    }

    public void setOnItemClickListener(final RecyclerListView.OnItemClickListener listener) {
        RecyclerListView recyclerListView = this.rv;
        if (recyclerListView != null) {
            recyclerListView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.discoveryweb.-$$Lambda$DiscoveryJumpMenuDialog$fn1hRgyisIsXuZXDTH3dC7LtWfg
                @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                public final void onItemClick(View view, int i) {
                    this.f$0.lambda$setOnItemClickListener$1$DiscoveryJumpMenuDialog(listener, view, i);
                }
            });
        }
    }

    public /* synthetic */ void lambda$setOnItemClickListener$1$DiscoveryJumpMenuDialog(RecyclerListView.OnItemClickListener listener, View view, int position) {
        dismiss();
        if (listener != null) {
            listener.onItemClick(view, position);
        }
    }

    private static class Holder extends RecyclerListView.Holder {
        static int TAG_IV = 1;
        static int TAG_TV = 2;
        ImageView iv;
        MryTextView tv;

        public Holder(View itemView) {
            super(itemView);
            this.iv = (ImageView) itemView.findViewWithTag(Integer.valueOf(TAG_IV));
            this.tv = (MryTextView) itemView.findViewWithTag(Integer.valueOf(TAG_TV));
        }
    }
}
