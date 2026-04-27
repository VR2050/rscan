package im.uwrkaxlmjj.ui.hui.adapter;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class KeyboardAdapter extends BaseAdapter {
    private Context mContext;
    private List<Integer> mNumbers;

    public KeyboardAdapter(List<Integer> mNumbers, Context mContext) {
        this.mNumbers = mNumbers;
        this.mContext = mContext;
    }

    @Override // android.widget.Adapter
    public int getCount() {
        List<Integer> list = this.mNumbers;
        if (list != null) {
            return list.size();
        }
        return 0;
    }

    @Override // android.widget.Adapter
    public Integer getItem(int position) {
        return this.mNumbers.get(position);
    }

    @Override // android.widget.Adapter
    public long getItemId(int position) {
        return position;
    }

    @Override // android.widget.Adapter
    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder holder;
        if (convertView == null) {
            convertView = View.inflate(this.mContext, R.layout.item_password_number, null);
            holder = new ViewHolder();
            holder.tvNumber = (TextView) convertView.findViewById(R.attr.btn_number);
            holder.ivDelete = (ImageView) convertView.findViewById(R.attr.iv_delete);
            convertView.setTag(holder);
        } else {
            holder = (ViewHolder) convertView.getTag();
        }
        if (position >= 9 && position != 10) {
            if (position == 9) {
                holder.tvNumber.setVisibility(4);
            } else if (position == 11) {
                holder.tvNumber.setVisibility(4);
                holder.ivDelete.setVisibility(0);
            }
        } else {
            holder.tvNumber.setText(String.valueOf(this.mNumbers.get(position)));
            holder.tvNumber.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        }
        return convertView;
    }

    class ViewHolder {
        ImageView ivDelete;
        TextView tvNumber;

        ViewHolder() {
        }
    }
}
