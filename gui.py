#!/usr/bin/env python3
"""
GUI for Log Analysis & CTI Tool with encoding and threading fixes
"""

import PySimpleGUI as sg
import subprocess
import os
import sys
import threading

# Set encoding to UTF-8 to handle special characters
os.environ['PYTHONUTF8'] = '1'

# Theme
sg.theme('DarkGrey5')


class LogAnalysisGUI:
    def __init__(self):
        self.running = False
        self.process = None
        self.analysis_successful = False
        self.setup_layout()

    def setup_layout(self):
        """Setup the GUI layout"""
        # Column layouts
        left_column = [
            [sg.Text('Log File:'), sg.Input(key='-LOG_FILE-', enable_events=True),
             sg.FileBrowse(file_types=(("Log Files", "*.log *.txt *.json"), ("All Files", "*.*")))],

            [sg.Text('Output Directory:'), sg.Input(key='-OUTPUT_DIR-', default_text='reports'),
             sg.FolderBrowse()],

            [sg.Text('Ollama Model:'), sg.Combo(['llama3:latest', 'phi:latest', 'mistral:latest'],
                                                default_value='llama3:latest', key='-OLLAMA_MODEL-')],

            [sg.Text('Ollama URL:'), sg.Input(key='-OLLAMA_URL-', default_text='http://localhost:11434')],

            [sg.HorizontalSeparator()],

            [sg.Text('API Keys (optional):')],
            [sg.Text('VirusTotal:'), sg.Input(key='-VT_KEY-', password_char='*',
                                              default_text='7e69992c45556821541a6a42e28cc9c4ce29b06287524c4ba3e013a37f0d8c05')],
            [sg.Text('AbuseIPDB:'), sg.Input(key='-ABUSEIPDB_KEY-', password_char='*')],

            [sg.HorizontalSeparator()],

            [sg.Button('Start Analysis', key='-START-', size=(15, 1)),
             sg.Button('Stop', key='-STOP-', size=(15, 1), disabled=True),
             sg.Button('Open Report', key='-OPEN_REPORT-', size=(15, 1), disabled=True)],

            [sg.Button('Exit', size=(15, 1))]
        ]

        right_column = [
            [sg.Multiline('Welcome to Log Analysis & CTI Tool\n\n'
                          '1. Select a log file to analyze\n'
                          '2. Choose output directory\n'
                          '3. Select AI model (requires Ollama)\n'
                          '4. Click "Start Analysis"\n\n'
                          'Status: Ready',
                          size=(70, 25), key='-OUTPUT-', autoscroll=True,
                          background_color='black', text_color='white')],

            [sg.ProgressBar(100, orientation='h', size=(50, 20), key='-PROGRESS-')],

            [sg.Text('Progress:'), sg.Text('0%', key='-PROGRESS_TEXT-', size=(5, 1))]
        ]

        # Full layout
        layout = [
            [sg.Text('Log Analysis & CTI Tool', font=('Helvetica', 16, 'bold'))],
            [sg.Column(left_column), sg.VerticalSeparator(), sg.Column(right_column)]
        ]

        # Create window with explicit encoding handling
        self.window = sg.Window('Log Analysis & CTI Tool', layout, finalize=True, resizable=True)

    def run(self):
        """Run the GUI main loop"""
        while True:
            event, values = self.window.read(timeout=100)

            if event == sg.WINDOW_CLOSED or event == 'Exit':
                break

            elif event == '-START-':
                if not values['-LOG_FILE-']:
                    sg.popup_error('Please select a log file first!')
                    continue

                if not os.path.exists(values['-LOG_FILE-']):
                    sg.popup_error('Log file does not exist!')
                    continue

                self.start_analysis(values)

            elif event == '-STOP-':
                self.stop_analysis()

            elif event == '-OPEN_REPORT-':
                if self.analysis_successful:
                    self.open_report(values['-OUTPUT_DIR-'])
                else:
                    sg.popup_error('Analysis was not successful. No reports to open.')

        self.window.close()

    def start_analysis(self, values):
        """Start the analysis in a separate thread"""
        self.running = True
        self.analysis_successful = False
        self.window['-START-'].update(disabled=True)
        self.window['-STOP-'].update(disabled=False)
        self.window['-OPEN_REPORT-'].update(disabled=True)

        # Clear output
        self.window['-OUTPUT-'].update('Starting analysis...\n')
        self.update_progress(5, "Starting")

        # Build command line arguments
        cmd = [
            sys.executable, '-u', 'main.py',
            values['-LOG_FILE-'],
            '--output', values['-OUTPUT_DIR-'],
            '--ollama-model', values['-OLLAMA_MODEL-'],
            '--ollama-url', values['-OLLAMA_URL-']
        ]

        # Add API keys if provided
        if values['-VT_KEY-'] and values['-VT_KEY-'] != "your_virustotal_api_key_here":
            cmd.extend(['--virustotal-key', values['-VT_KEY-']])
        if values['-ABUSEIPDB_KEY-']:
            cmd.extend(['--abuseipdb-key', values['-ABUSEIPDB_KEY-']])

        # Start analysis in separate thread
        thread = threading.Thread(target=self.run_analysis_thread, args=(cmd, values['-OUTPUT_DIR-']))
        thread.daemon = True
        thread.start()

    def run_analysis_thread(self, cmd, output_dir):
        """Run analysis in separate thread using subprocess"""
        try:
            # Set UTF-8 encoding for subprocess
            env = os.environ.copy()
            env['PYTHONUTF8'] = '1'

            self.append_output("Running analysis...\n")
            self.append_output(f"Command: {' '.join(cmd[:4])}...\n")

            # Run the process with UTF-8 encoding
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                env=env,
                encoding='utf-8',
                errors='ignore'  # Ignore encoding errors
            )

            # Read output in real-time
            for line in iter(self.process.stdout.readline, ''):
                if not self.running:
                    self.process.terminate()
                    break

                # Clean the line of any problematic characters
                cleaned_line = line.encode('utf-8', 'ignore').decode('utf-8').strip()
                if cleaned_line:
                    self.append_output(cleaned_line)

                # Update progress based on certain messages
                if 'Parsing log file' in cleaned_line:
                    self.update_progress(20, "Parsing logs")
                elif 'Enriching with CTI data' in cleaned_line:
                    self.update_progress(40, "CTI enrichment")
                elif 'Initializing Local Llama AI' in cleaned_line:
                    self.update_progress(60, "AI analysis")
                elif 'Generating report' in cleaned_line:
                    self.update_progress(80, "Generating report")
                elif 'Analysis complete!' in cleaned_line:
                    self.update_progress(95, "Finalizing")

            # Wait for process to complete
            return_code = self.process.wait()

            if self.running:
                if return_code == 0:
                    self.analysis_complete(output_dir)
                else:
                    self.analysis_failed(return_code)
            else:
                self.append_output("Analysis stopped by user.")
                self.window['-START-'].update(disabled=False)
                self.window['-STOP-'].update(disabled=True)

        except Exception as e:
            error_msg = f"Error during analysis: {str(e)}"
            self.append_output(error_msg)
            self.window['-START-'].update(disabled=False)
            self.window['-STOP-'].update(disabled=True)

    def stop_analysis(self):
        """Stop the analysis"""
        self.running = False
        if self.process:
            self.process.terminate()
        self.append_output("Analysis stopped by user.")
        self.window['-START-'].update(disabled=False)
        self.window['-STOP-'].update(disabled=True)
        self.update_progress(0, "Stopped")

    def analysis_complete(self, output_dir):
        """Handle analysis completion"""
        self.running = False
        self.analysis_successful = True
        self.window['-START-'].update(disabled=False)
        self.window['-STOP-'].update(disabled=True)
        self.window['-OPEN_REPORT-'].update(disabled=False)

        # Update progress to 100%
        self.update_progress(100, "Complete!")

        # Show completion message
        self.append_output("\nAnalysis completed successfully!")
        self.append_output(f"Reports saved to: {output_dir} \n")
        self.append_output("\nClick 'Open Report' to view the results.")

    def analysis_failed(self, return_code):
        """Handle analysis failure"""
        self.running = False
        self.analysis_successful = False
        self.window['-START-'].update(disabled=False)
        self.window['-STOP-'].update(disabled=True)
        self.window['-OPEN_REPORT-'].update(disabled=True)

        self.append_output(f"\nAnalysis failed with return code: {return_code}")
        self.append_output("Please check the error messages above and try again.")
        self.update_progress(0, "Failed")

        # Show error popup
        try:
            sg.popup_error('Analysis failed!', 'Please check the output for error details.')
        except:
            pass  # Silently fail if popup doesn't work

    def append_output(self, text):
        """Append text to the output area with encoding handling"""
        if text.strip():
            try:
                # Clean the text of any problematic Unicode characters
                cleaned_text = text.encode('utf-8', 'ignore').decode('utf-8')
                current = self.window['-OUTPUT-'].get()
                self.window['-OUTPUT-'].update(current + cleaned_text + '\n')
                self.window.refresh()
            except Exception as e:
                # Fallback: simple print to console
                print(f"GUI output error: {e}")

    def update_progress(self, value, text=None):
        """Update progress bar"""
        try:
            self.window['-PROGRESS-'].update(value)
            if text:
                self.window['-PROGRESS_TEXT-'].update(f'{value}% - {text}')
            self.window.refresh()
        except:
            pass  # Silently fail if progress update doesn't work

    def open_report(self, output_dir):
        """Open the report directory"""
        if os.path.exists(output_dir):
            try:
                # Open directory in file explorer
                if os.name == 'nt':  # Windows
                    os.startfile(output_dir)
                elif os.name == 'posix':  # macOS, Linux
                    os.system(f'xdg-open "{output_dir}"')
            except Exception as e:
                try:
                    sg.popup_error(f"Could not open directory: {str(e)}")
                except:
                    pass
        else:
            try:
                sg.popup_error("Output directory does not exist!")
            except:
                pass


def main():
    """Main function to run the GUI"""
    try:
        gui = LogAnalysisGUI()
        gui.run()
    except Exception as e:
        print(f"GUI failed to start: {e}")
        print("Try running from command line: python main.py your_log_file.log")


if __name__ == "__main__":
    main()