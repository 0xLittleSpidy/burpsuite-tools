// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jwtcomparator.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.littlespidy.jwtcomparator.attacker.model.JwtTokenInjector;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/** Serial, throttled attack-variant probes against requests explicitly queued from Burp. */
public class LiveJwtProbePanel extends JPanel {
    private final MontoyaApi api;
    private final JwtAttackWorkbenchPanel workbench;
    private final List<HttpRequestResponse> queued = new ArrayList<>();
    private final JTextArea tokens = new JTextArea(4, 70);
    private final JComboBox<String> placement = new JComboBox<>(new String[]{"header", "cookie", "query", "body"});
    private final JTextField name = new JTextField("Authorization", 18);
    private final JTextField prefix = new JTextField("Bearer ", 12);
    private final JSpinner delay = new JSpinner(new SpinnerNumberModel(250, 0, 10000, 50));
    private final JTextField expectedCanary=new JTextField(24);
    private final JLabel queueStatus = new JLabel("No requests queued. Use the Burp context menu to add authorized targets.");
    private final DefaultTableModel model = new DefaultTableModel(new Object[]{"Request", "JWT", "Status", "Size", "Assessment"}, 0) {
        @Override public boolean isCellEditable(int row, int col) { return false; }
    };
    private final JButton start = new JButton("Probe queued requests");
    private final JButton stop = new JButton("Stop");
    private SwingWorker<Void, Object[]> worker;

    public LiveJwtProbePanel(MontoyaApi api, JwtAttackWorkbenchPanel workbench) {
        super(new BorderLayout(5,5)); this.api=api; this.workbench=workbench;
        JPanel config=new JPanel(new GridBagLayout()); config.setBorder(BorderFactory.createTitledBorder("Live probes — manually review and authorize targets"));
        GridBagConstraints c=new GridBagConstraints(); c.insets=new Insets(3,5,3,5); c.fill=GridBagConstraints.HORIZONTAL; c.weightx=1;
        c.gridx=0;c.gridy=0;c.gridwidth=5;config.add(new JLabel("Paste one JWT per line. Probes are sent serially to requests explicitly added from Burp; no hostname or URL is accepted here."),c);
        c.gridy++;config.add(new JScrollPane(tokens),c);
        c.gridwidth=1;c.gridy++;c.weightx=0;config.add(new JLabel("Token location:"),c); c.gridx=1;config.add(placement,c);
        c.gridx=2;config.add(new JLabel("Field name:"),c); c.gridx=3;config.add(name,c); c.gridx=4;config.add(prefix,c);
        placement.addActionListener(e->{ boolean header="header".equals(placement.getSelectedItem()); name.setText(header?"Authorization":"token"); prefix.setText(header?"Bearer ":""); });
        c.gridx=0;c.gridy++;c.weightx=0;config.add(new JLabel("Expected canary (optional):"),c);c.gridx=1;c.gridwidth=4;c.weightx=1;config.add(expectedCanary,c);
        JPanel buttons=new JPanel(new FlowLayout(FlowLayout.LEFT)); start.addActionListener(e->runProbes()); stop.setEnabled(false); stop.addActionListener(e->{if(worker!=null)worker.cancel(true);});
        JButton importVariants=new JButton("Import generated variants"); importVariants.addActionListener(e->importVariants()); buttons.add(importVariants);
        buttons.add(start);buttons.add(stop);buttons.add(new JLabel("Delay between requests (ms):"));buttons.add(delay); JButton clear=new JButton("Clear results / queue");clear.addActionListener(e->{if(worker==null||worker.isDone()){queued.clear();model.setRowCount(0);updateQueueLabel();}});buttons.add(clear);
        c.gridx=0;c.gridy++;c.gridwidth=5;config.add(buttons,c); c.gridy++;config.add(queueStatus,c);
        JTable table=new JTable(model);table.setAutoCreateRowSorter(true);table.setFillsViewportHeight(true);
        add(config,BorderLayout.NORTH);add(new JScrollPane(table),BorderLayout.CENTER);
        add(new JLabel("Assessment compares status and response size to the captured baseline; changed responses are leads for manual review, not confirmed vulnerabilities."),BorderLayout.SOUTH);
    }
    public synchronized void addRequests(List<HttpRequestResponse> items) {
        if(items==null)return;
        for(HttpRequestResponse item:items) if(item!=null&&item.request()!=null) queued.add(item);
        updateQueueLabel();
    }
    private synchronized void updateQueueLabel(){queueStatus.setText("Queued requests: "+queued.size()+" | Requests are replayed only after you press Probe.");}
    private void runProbes(){
        if(api==null||api.http()==null){append("", "", "", "", "Burp HTTP API unavailable");return;}
        List<String> variants=new ArrayList<>(); for(String line:tokens.getText().split("\\R")){String t=line.trim();if(t.regionMatches(true,0,"Bearer ",0,7))t=t.substring(7).trim();if(t.split("\\.",-1).length==3)variants.add(t);}
        if(variants.isEmpty()){append("", "", "", "", "Paste at least one three-part JWT, one per line.");return;}
        List<HttpRequestResponse> targets; synchronized(this){targets=new ArrayList<>(queued);}
        if(targets.isEmpty()){append("", "", "", "", "Queue an authorized request from Burp first.");return;}
        String where=(String)placement.getSelectedItem(), field=name.getText().trim(), pre=prefix.getText(), canary=expectedCanary.getText(); int pause=(int)delay.getValue();
        start.setEnabled(false);stop.setEnabled(true);
        worker=new SwingWorker<>(){
            protected Void doInBackground(){
                for(HttpRequestResponse original:targets){
                    if(isCancelled())break;
                    HttpRequest req=original.request(); int baseStatus=original.hasResponse()?original.response().statusCode():-1; int baseSize=original.hasResponse()?original.response().body().length():-1;
                    for(String jwt:variants){
                        if(isCancelled())break;
                        try{
                            var result=api.http().sendRequest(JwtTokenInjector.injectToken(req,jwt,where,field,pre));
                            if(result==null||!result.hasResponse()){publish(new Object[]{req.url(),shortToken(jwt),"No response","", "Request failed"});}
                            else {HttpResponse response=result.response();int status=response.statusCode(),size=response.body().length();String assess=assess(baseStatus,baseSize,status,size,response.bodyToString(),canary);publish(new Object[]{req.url(),shortToken(jwt),String.valueOf(status),String.valueOf(size),assess});}
                        }catch(Exception ex){publish(new Object[]{req.url(),shortToken(jwt),"Error","",ex.getMessage()==null?"Probe failed":ex.getMessage()});}
                        if(pause>0&&!isCancelled())try{Thread.sleep(pause);}catch(InterruptedException ex){Thread.currentThread().interrupt();return null;}
                    }
                }
                return null;
            }
            protected void process(List<Object[]> rows){for(Object[] row:rows)model.addRow(row);}
            protected void done(){start.setEnabled(true);stop.setEnabled(false);}
        }; worker.execute();
    }
    private static String assess(int baselineStatus,int baselineSize,int status,int size,String body,String canary){
        if(canary!=null&&!canary.isBlank()&&body.contains(canary))return "Expected canary matched — review authorization";
        if(status>=500)return "Server error — inspect for parsing failure";
        if((baselineStatus==401||baselineStatus==403)&&status>=200&&status<300)return "Potential auth bypass — review response";
        if(baselineStatus>=0&&status!=baselineStatus)return "Status differs from baseline — review";
        if(baselineSize>0&&Math.abs(size-baselineSize)>Math.max(64,baselineSize/5))return "Response size differs — review";
        return "No obvious response difference";
    }
    private static String shortToken(String token){return token.length()<28?token:token.substring(0,12)+"…"+token.substring(token.length()-8);}
    private void importVariants(){
        if(workbench==null)return;
        List<String> generated=workbench.getGeneratedTokens(); if(generated.isEmpty()){append("","","","","Generate JWT variants in JWT Attack Workbench first.");return;}
        java.util.LinkedHashSet<String> all=new java.util.LinkedHashSet<>(); for(String line:tokens.getText().split("\\R"))if(!line.isBlank())all.add(line.trim()); all.addAll(generated);
        tokens.setText(String.join("\n",all)); append("","",String.valueOf(generated.size()),"","Imported unique generated JWT variants.");
    }
    private void append(String a,String b,String c,String d,String e){model.addRow(new Object[]{a,b,c,d,e});}
    public void stopProbes(){if(worker!=null&&!worker.isDone())worker.cancel(true);}
}
