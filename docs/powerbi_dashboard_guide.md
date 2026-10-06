# Power BI Dashboard Guide

A step-by-step guide to build and publish an interactive AWS FinOps dashboard using Power BI Desktop and the findings dataset.

## Section 1: Prerequisites

Before starting, ensure you have the following:

1. **Power BI Desktop** (free version)
   - Download from [Microsoft Store](https://www.microsoft.com/store) or [microsoft.com](https://www.microsoft.com/en-us/download/details.aspx?id=58494)
   - Install on your local machine

2. **Generate the findings dataset**
   - Navigate to the project root directory in your terminal
   - Run the command: `python build_dataset.py`
   - This creates `dataset/findings_dataset.csv` with all findings from recent scans
   - The dataset includes columns: `snapshot_date`, `wave`, `source_script`, `account_id`, `region`, `resource_type`, `resource_id`, `finding`, `detail`, `severity`, `estimated_monthly_savings_usd`, `estimated_annual_savings_usd`, and org tags

3. **For cloud publishing** (optional)
   - Identify a teammate with a Power BI Pro license for publishing to cloud workspaces
   - They will use their account to publish the final dashboard to SharePoint or Teams

## Section 2: Load the Dataset

1. **Open Power BI Desktop**
   - Launch Power BI Desktop from your Start menu or taskbar

2. **Import the CSV file**
   - Click **Get Data** in the ribbon
   - Select **Text/CSV**
   - Navigate to `dataset/findings_dataset.csv` and select it
   - Click **Load** (or **Transform Data** if you want to preview first)

3. **Set column data types in Power Query Editor** (if not auto-detected correctly)
   - Right-click the `snapshot_date` column header → **Change Type** → **Date**
   - Right-click `estimated_monthly_savings_usd` → **Change Type** → **Decimal Number**
   - Right-click `estimated_annual_savings_usd` → **Change Type** → **Decimal Number**
   - Leave all other columns as **Text**
   - Click **Close & Apply** to load the data into your data model

4. **Verify the load**
   - You should see the data appear in the **Data** pane on the right
   - The table will be named `findings_dataset` by default
   - Confirm row count matches your CSV

## Section 3: Create Measures (DAX)

Measures allow you to create dynamic calculations that respond to slicing and filtering.

1. **Create a Measures table**
   - In the **Modeling** tab, click **New Table**
   - Enter this formula and press Enter:
     ```dax
     Measures = ROW("Placeholder", 1)
     ```
   - This creates an empty table to hold your measures (best practice for organization)

2. **Add measures one by one**
   - Select the **Measures** table
   - In the **Modeling** tab, click **New Measure**
   - For each measure below, enter the name and formula, then press Enter

3. **Total Monthly Savings**
   - Name: `Total Monthly Savings`
   - Formula:
     ```dax
     Total Monthly Savings = SUM(findings_dataset[estimated_monthly_savings_usd])
     ```

4. **Total Annual Savings**
   - Name: `Total Annual Savings`
   - Formula:
     ```dax
     Total Annual Savings = SUM(findings_dataset[estimated_annual_savings_usd])
     ```

5. **Total Findings**
   - Name: `Total Findings`
   - Formula:
     ```dax
     Total Findings = COUNTROWS(findings_dataset)
     ```

6. **High Severity Count**
   - Name: `High Severity Count`
   - Formula:
     ```dax
     High Severity Count = COUNTROWS(FILTER(findings_dataset, findings_dataset[severity] = "High"))
     ```

7. **Latest Snapshot**
   - Name: `Latest Snapshot`
   - Formula:
     ```dax
     Latest Snapshot = MAX(findings_dataset[snapshot_date])
     ```

8. **Latest Snapshot Savings**
   - Name: `Latest Snapshot Savings`
   - Formula:
     ```dax
     Latest Snapshot Savings = CALCULATE([Total Monthly Savings], findings_dataset[snapshot_date] = MAX(findings_dataset[snapshot_date]))
     ```

9. **Previous Snapshot Savings**
   - Name: `Prev Snapshot Savings`
   - Formula:
     ```dax
     Prev Snapshot Savings = CALCULATE([Total Monthly Savings], findings_dataset[snapshot_date] = MAXX(FILTER(ALL(findings_dataset), findings_dataset[snapshot_date] < MAX(findings_dataset[snapshot_date])), findings_dataset[snapshot_date]))
     ```

10. **Savings Delta**
    - Name: `Savings Delta`
    - Formula:
      ```dax
      Savings Delta = [Latest Snapshot Savings] - [Prev Snapshot Savings]
      ```

**Important filtering note:** When you add a `snapshot_date` slicer to your pages, the report will automatically filter to show the latest snapshot only by default. This is because Power BI respects the filter context. The Trends page (Section 4, Page 4) should omit the date slicer so that all dates display in the time-series charts.

## Section 4: Report Pages

Create four report pages with the visualizations below. Start by clicking the **+** icon at the bottom of the screen to add a new page.

### Page 1: Overview

This is your executive summary dashboard.

1. **Add KPI Cards** (top section)
   - Click **Card** visual from the Visualizations pane
   - Drag `[Total Monthly Savings]` into the visual
   - Repeat for: `[Total Annual Savings]`, `[Total Findings]`, `[High Severity Count]`
   - Arrange in a 2x2 or 1x4 grid at the top

2. **Add Monthly Savings by Wave (bar chart)**
   - Click **Bar Chart** visual
   - Drag `wave` to the X-axis
   - Drag `[Total Monthly Savings]` to the Y-axis
   - Title: "Monthly Savings by Wave"
   - Position below KPI cards on the left

3. **Add Findings by Severity (donut chart)**
   - Click **Donut Chart** visual
   - Drag `severity` to Legend
   - Drag `[Total Findings]` to Values
   - Title: "Findings by Severity"
   - Position on the right, same height as the bar chart

4. **Add Snapshot Date Slicer**
   - Click **Slicer** visual
   - Drag `snapshot_date` to the slicer
   - Position at the top right or bottom left
   - **Important:** By default, slicers show all values. To display the latest date prominently, hover over the slicer and select the most recent date (or leave all selected to allow manual filtering)

5. **Add Top 10 Findings Table**
   - Click **Table** visual
   - Add columns in this order: `account_id`, `region`, `resource_type`, `finding`, `estimated_monthly_savings_usd`
   - Click the **...** menu on `estimated_monthly_savings_usd` → **Sort descending** (to show highest savings first)
   - In the visual filters pane (top of Visualizations), add a top N filter: Top 10 by `estimated_monthly_savings_usd`
   - Title: "Top 10 Findings by Monthly Savings"
   - Position below the bar and donut charts, spanning the full width

### Page 2: Cost

This page focuses on Wave 1 findings (cost optimization opportunities).

1. **Add a page-level filter**
   - In the **Filters** pane (right side), click **Add filter** → **Filter on this page**
   - Drag `wave` to the filter box
   - Select only `wave1_cost`
   - All visuals on this page will now show only cost findings

2. **Add Top Accounts by Savings (bar chart)**
   - Click **Bar Chart** visual
   - Drag `account_id` to the X-axis
   - Drag `[Total Monthly Savings]` to the Y-axis
   - Sort by savings descending
   - Title: "Monthly Savings by Account"
   - Position on the top half

3. **Add Cost Findings Table**
   - Click **Table** visual
   - Add columns: `account_id`, `region`, `resource_type`, `resource_id`, `finding`, `detail`, `estimated_monthly_savings_usd`
   - Sort by estimated_monthly_savings_usd descending
   - Title: "All Cost Findings"
   - Position below, spanning full width

4. **Add snapshot_date slicer** (same as Overview page)

### Page 3: Security

This page focuses on Wave 4 findings (security posture).

1. **Add a page-level filter**
   - In the **Filters** pane, click **Add filter** → **Filter on this page**
   - Drag `wave` to the filter box
   - Select only `wave4_security`

2. **Add Findings by Type (bar chart)**
   - Click **Bar Chart** visual
   - Drag `finding` to the X-axis
   - Drag `[Total Findings]` to the Y-axis
   - Title: "Security Findings by Type"
   - Position on the top half

3. **Add Security Findings Table**
   - Click **Table** visual
   - Add columns: `account_id`, `region`, `resource_type`, `finding`, `detail`, `severity`
   - Click the **...** menu on the `severity` column → **Conditional formatting** → **Background color**
   - Set: "High" = red, "Medium" = yellow, "Low" = green
   - Title: "All Security Findings"
   - Position below, spanning full width

4. **Add snapshot_date slicer**

### Page 4: Trends

This page shows historical trends and should **not** have a snapshot_date slicer (so all dates display).

1. **Important:** Do not add a snapshot_date slicer to this page
   - This page will show data across all snapshots in your dataset
   - Meaningful trends require at least 2-3 snapshot dates (multiple scan runs)

2. **Add Total Monthly Savings Over Time (line chart)**
   - Click **Line Chart** visual
   - Drag `snapshot_date` to the X-axis
   - Drag `[Total Monthly Savings]` to the Y-axis
   - Title: "Monthly Savings Trend"
   - Position on the top half

3. **Add Findings Count by Severity Over Time (multi-series line chart)**
   - Click **Line Chart** visual
   - Drag `snapshot_date` to the X-axis
   - Drag `[Total Findings]` to the Y-axis
   - Drag `severity` to the Legend
   - This will show three lines (High, Medium, Low) over time
   - Title: "Findings by Severity Over Time"
   - Position below

4. **Add a note**
   - Add a **Text box** at the top with: "Trends are only meaningful once you have multiple snapshot dates. After each scan run, refresh the dataset in Power BI."

## Section 5: Publish via Teammate's Pro License

Once your dashboard is complete and tested locally, publish it to the cloud workspace.

1. **Save your file**
   - Click **File** → **Save As**
   - Choose a location (e.g., `reports/aws_finops_dashboard.pbix`)
   - Use a descriptive filename

2. **Share the .pbix file with your teammate**
   - Send the saved .pbix file to your teammate who has a Power BI Pro license
   - They will need to open it on their machine

3. **Teammate publishes to the cloud** (Pro license required)
   - Teammate opens the .pbix file in Power BI Desktop
   - Click **Publish** in the ribbon
   - Choose or create a workspace (e.g., "CloudOps Dashboards")
   - Click **Select**
   - Power BI uploads the dashboard to the cloud

4. **Share the published dashboard**
   - Once published, the teammate can:
     - Invite users via the workspace settings
     - Embed the dashboard link in Teams or SharePoint
     - Generate a shareable link for read-only access

5. **Alternative: Direct .pbix sharing** (no Pro license needed for viewers)
   - If cloud publishing is not needed, you can share the .pbix file directly with colleagues
   - Colleagues with Power BI Desktop (free) can open and view the dashboard locally
   - They cannot edit it unless they also create their own copy

## Section 6: Keeping Data Fresh

After each AWS scan cycle, update your dashboard with the latest findings.

1. **Generate updated dataset**
   - Run: `python build_dataset.py`
   - This appends the new snapshot to `dataset/findings_dataset.csv`

2. **Refresh data in Power BI Desktop**
   - Open your .pbix file
   - Click **Home** → **Refresh**
   - Power BI will automatically import the new rows
   - All measures and visuals will update instantly

3. **Re-publish if using cloud workspace** (Pro license required)
   - Click **Publish** again
   - Power BI will overwrite the previous version in the workspace
   - Colleagues viewing the dashboard online will see the latest data on their next refresh

4. **Track refresh timing**
   - The `Latest Snapshot` measure always points to the most recent scan date
   - Add this measure to a card on your Overview page to show when the data was last updated

## Troubleshooting

**Q: My snapshot_date column shows as text instead of date**
- In Power Query Editor, right-click the column → **Change Type** → **Date** → **Close & Apply**

**Q: Measures are showing 0 or blank**
- Ensure the findings_dataset table was loaded successfully
- Verify that numeric columns (`estimated_monthly_savings_usd`, etc.) are set to Decimal Number type, not Text
- Check that your DAX syntax is correct (use the formula bar error messages as a guide)

**Q: How do I filter to just the latest snapshot?**
- Add a `snapshot_date` slicer to your page
- Click the slicer dropdown → select only the most recent date
- The measures will automatically recalculate

**Q: Can I publish without a Pro license?**
- No. Cloud publishing (to Teams, SharePoint, or Power BI workspaces) requires a Power BI Pro license
- You can share the .pbix file directly; recipients can open it in Power BI Desktop (free)

**Q: How do I add more org tags to my dashboard?**
- If your dataset includes additional tag columns (e.g., `tag_Application`), drag them into slicers or visuals just like `wave` or `severity`
- No code changes needed
