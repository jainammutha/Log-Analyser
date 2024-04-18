from flask import Flask, render_template, request, make_response
import re
from collections import Counter
import reportlab.pdfgen.canvas as canvas  # For PDF reports
import io
import openpyxl  # For Excel reports
import reportlab.pdfgen as rl
import matplotlib.pyplot as plt  # For creating pie charts
import base64


app = Flask(__name__)

def parse_log_entry(log):
    pattern = r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(\w+)\((\w+)\)\[(\d+)\]:\s+(.*)"
    match = re.search(pattern, log)
    if match:
        month_day_time = match.group(1)
        hostname = match.group(2)
        component = match.group(3)
        subsystem = match.group(4)
        pid = match.group(5)
        message = match.group(6)

        return {
            'month_day_time': month_day_time,
            'hostname': hostname,
            'component': component,
            'subsystem': subsystem,
            'pid': pid,
            'message': message
        }
    else:
        return None

def analyze_event_logs_for_brute_force(error_message):
    # Assuming brute force is determined based on specific conditions in the error message
    if "brute force" in error_message.lower():
        return "brute force"
    else:
        return None

def analyze_event_logs(parsed_logs):
    error_count = 0
    pattern = r"authentication failure"

    for log_entry in parsed_logs:
        if 'message' in log_entry:
            message = log_entry['message']
            if re.search(pattern, message, re.IGNORECASE):
                error_count += 1
    
    if error_count > 0:
        return f"The main problem is likely caused by {error_count} errors in the event logs."
    else:
        return "No significant errors were found in the event logs."

def check_error_repeats(parsed_logs, threshold=4):
    error_counts = Counter()
    current_errors = {}  # Dictionary to store counts for each error message
    for log_entry in parsed_logs:
        if 'message' in log_entry and 'month_day_time' in log_entry:
            message = log_entry['message']
            timestamp = log_entry['month_day_time']
            # Check if the message contains "authentication failure"
            if "authentication failure" in message.lower():
                if message in current_errors:
                    current_errors[message]['count'] += 1
                else:
                    current_errors[message] = {'timestamp': timestamp, 'count': 1}
    
    # Add errors exceeding threshold to the error_counts counter
    for error, data in current_errors.items():
        if data['count'] >= threshold:
            error_counts[(error, data['timestamp'])] = data['count']
    
    repeated_errors = [{'message': error[0], 'timestamp': error[1], 'count': count} for error, count in error_counts.items()]
    
    return repeated_errors if repeated_errors else None




def identify_patterns(logs):
    message_counts = Counter()
    for entry in logs:
        message_counts[entry['message']] += 1
    return message_counts

def identify_anomalies(logs, pattern_threshold=0.1):
    total_messages = len(logs)
    common_patterns = identify_patterns(logs)
    pattern_counts = sum(common_patterns.values())
    anomalies = []
    for message, count in common_patterns.items():
        if count / total_messages > pattern_threshold - (count / pattern_counts):
            anomaly = {'message': message, 'count': count}
            anomalies.append(anomaly)
    return anomalies

def identify_failures(event_logs):
    failures = []
    failure_patterns = [
        r"authentication failure",
        r"check pass"
    ]
    combined_pattern = re.compile("|".join(failure_patterns), re.IGNORECASE)

    failure_counts = Counter()
    for log_entry in event_logs:
        message = log_entry['message']
        if combined_pattern.search(message):
            failure_counts[message] += 1

    threshold = 1
    for message, count in failure_counts.items():
        if count >= threshold:
            failures.append({'message': message, 'count': count})

    return failures

def generate_pie_chart(common_patterns):
    labels = list(common_patterns.keys())
    counts = list(common_patterns.values())

    plt.figure(figsize=(8, 6))
    plt.pie(counts, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    plt.title('Common Patterns Pie Chart')

    # Save the plot to a buffer
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    plt.close()  # Close the plot to free up memory

    # Encode the image buffer in base64 format
    encoded_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
    
    return encoded_image


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/parse_logs', methods=['POST'])
def parse_logs():
    if 'log_files' not in request.files:
        return render_template('error.html', message='No log files uploaded.')

    log_files = request.files.getlist('log_files')
    if not log_files:
        return render_template('error.html', message='No selected files.')

    parsed_logs = []
    for log_file in log_files:
        if log_file.filename == '':
            continue 
        for line in log_file:
            try:
                log_entry = line.decode('utf-8').strip()
            except UnicodeDecodeError:
                log_entry = line.decode('latin-1').strip()  
            parsed_log = parse_log_entry(log_entry)
            if parsed_log is not None:
                parsed_logs.append(parsed_log)
        
    failures = identify_failures(parsed_logs)
    root_cause = analyze_event_logs(parsed_logs)
    common_patterns = identify_patterns(parsed_logs)
    anomalies = identify_anomalies(parsed_logs)
    repeated_errors = check_error_repeats(parsed_logs)
    pie_chart = generate_pie_chart(common_patterns)

    return render_template('result.html', 
                           parsed_logs=parsed_logs, 
                           root_cause=root_cause, 
                           common_patterns=common_patterns, 
                           anomalies=anomalies,
                           failures=failures,
                           repeated_errors=repeated_errors,
                           pie_chart=pie_chart)

def generate_pdf_report(report_data):
    # Create a PDF document
    buffer = io.BytesIO()
    pdf_canvas = canvas.Canvas(buffer)

    # Write report content to the PDF
    pdf_canvas.drawString(100, 800, "PDF Report")

    # Save the PDF
    pdf_canvas.save()

    # Return the PDF content
    buffer.seek(0)
    return buffer.read()

def generate_excel_report(report_data):
    # Create a new Excel workbook
    wb = openpyxl.Workbook()
    ws = wb.active

    # Add headers
    headers = ['Message', 'Count']
    ws.append(headers)

    # Write data to the Excel sheet
    for anomaly in report_data['anomalies']:
        ws.append([anomaly['message'], anomaly['count']])

    # Save the Excel workbook to a buffer
    buffer = io.BytesIO()
    wb.save(buffer)

    # Return the Excel file content
    buffer.seek(0)
    return buffer.getvalue()

def generate_excel_report(report_data):
    # Create a new Excel workbook
    wb = openpyxl.Workbook()
    ws = wb.active

    # Add headers
    headers = ['Message', 'Count']
    ws.append(headers)

    # Write data to the Excel sheet
    for anomaly in report_data['anomalies']:
        ws.append([anomaly['message'], anomaly['count']])

    # Save the Excel workbook to a buffer
    buffer = io.BytesIO()
    wb.save(buffer)

    # Return the Excel file content
    buffer.seek(0)
    return buffer.getvalue()

@app.route('/query', methods=['POST'])
def generate_report():
    # Get the requested report format from the form
    report_format = request.form.get('reportFormat')

    # Prepare the report data based on parsed_logs and other analysis results
    parsed_logs = request.form.get('parsed_logs')  # Retrieve parsed logs from form data
    root_cause = request.form.get('root_cause')  # Retrieve root cause from form data
    common_patterns = request.form.get('common_patterns')  # Retrieve common patterns from form data
    anomalies = request.form.get('anomalies')  # Retrieve anomalies from form data
    failures = request.form.get('failures')  # Retrieve failures from form data
    repeated_errors = request.form.get('repeated_errors')  # Retrieve repeated errors from form data
    
    report_data = {
        'common_patterns': common_patterns,
        'anomalies': anomalies,
        'failures': failures,
        'repeated_errors': repeated_errors,
        'parsed_logs': parsed_logs,
        'root_cause': root_cause,
    }

    # Generate the report using a chosen library
    if report_format == 'pdf':
        report = generate_pdf_report(report_data)
        content_type = 'application/pdf'
    else:
        report = generate_excel_report(report_data)
        content_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

    # Send the report as a response (consider content type and attachment)
    response = make_response(report)
    response.headers['Content-Type'] = content_type
    response.headers['Content-Disposition'] = f'attachment; filename=report.{report_format}'
    return response

if __name__ == '__main__':
    app.run(debug=True)