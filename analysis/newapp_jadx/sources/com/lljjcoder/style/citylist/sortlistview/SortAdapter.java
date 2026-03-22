package com.lljjcoder.style.citylist.sortlistview;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.SectionIndexer;
import android.widget.TextView;
import com.lljjcoder.style.citypickerview.C3949R;
import java.util.List;

/* loaded from: classes2.dex */
public class SortAdapter extends BaseAdapter implements SectionIndexer {
    private List<SortModel> list;
    private Context mContext;

    public static final class ViewHolder {
        public TextView tvLetter;
        public TextView tvTitle;
    }

    public SortAdapter(Context context, List<SortModel> list) {
        this.list = null;
        this.mContext = context;
        this.list = list;
    }

    private String getAlpha(String str) {
        String upperCase = str.trim().substring(0, 1).toUpperCase();
        return upperCase.matches("[A-Z]") ? upperCase : "#";
    }

    @Override // android.widget.Adapter
    public int getCount() {
        return this.list.size();
    }

    @Override // android.widget.Adapter
    public Object getItem(int i2) {
        return this.list.get(i2);
    }

    @Override // android.widget.Adapter
    public long getItemId(int i2) {
        return i2;
    }

    @Override // android.widget.SectionIndexer
    public int getPositionForSection(int i2) {
        for (int i3 = 0; i3 < getCount(); i3++) {
            if (this.list.get(i3).getSortLetters().toUpperCase().charAt(0) == i2) {
                return i3;
            }
        }
        return -1;
    }

    @Override // android.widget.SectionIndexer
    public int getSectionForPosition(int i2) {
        return this.list.get(i2).getSortLetters().charAt(0);
    }

    @Override // android.widget.SectionIndexer
    public Object[] getSections() {
        return null;
    }

    @Override // android.widget.Adapter
    public View getView(int i2, View view, ViewGroup viewGroup) {
        View view2;
        ViewHolder viewHolder;
        if (view == null) {
            viewHolder = new ViewHolder();
            view2 = LayoutInflater.from(this.mContext).inflate(C3949R.layout.sortlistview_item, (ViewGroup) null);
            viewHolder.tvTitle = (TextView) view2.findViewById(C3949R.id.title);
            viewHolder.tvLetter = (TextView) view2.findViewById(C3949R.id.catalog);
            view2.setTag(viewHolder);
        } else {
            view2 = view;
            viewHolder = (ViewHolder) view.getTag();
        }
        List<SortModel> list = this.list;
        if (list != null && !list.isEmpty()) {
            SortModel sortModel = this.list.get(i2);
            if (i2 == getPositionForSection(getSectionForPosition(i2))) {
                viewHolder.tvLetter.setVisibility(0);
                viewHolder.tvLetter.setText(sortModel.getSortLetters());
            } else {
                viewHolder.tvLetter.setVisibility(8);
            }
            viewHolder.tvTitle.setText(this.list.get(i2).getName());
        }
        return view2;
    }

    public void updateListView(List<SortModel> list) {
        this.list = list;
        notifyDataSetChanged();
    }
}
