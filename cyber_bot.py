from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
import subprocess
import shodan
import pyshark

# Shodan API Key
SHODAN_API_KEY = 'YOUR_SHODAN_API_KEY'

# Nmap Scan Function
async def nmap_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    target = ' '.join(context.args)
    if not target:
        await update.message.reply_text('Please provide a target to scan.')
        return

    result = subprocess.run(['nmap', target], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')
    await update.message.reply_text(f"Scan result for {target}:\n\n{output}")

# Nuclei Scan Function
async def nuclei_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    target = ' '.join(context.args)
    if not target:
        await update.message.reply_text('Please provide a target to scan.')
        return

    result = subprocess.run(['nuclei', '-u', target], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')
    await update.message.reply_text(f"Nuclei scan result for {target}:\n\n{output}")

# Shodan Search Function
async def shodan_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = ' '.join(context.args)
    if not query:
        await update.message.reply_text('Please provide a search query.')
        return

    api = shodan.Shodan(SHODAN_API_KEY)
    results = api.search(query)
    
    if results['total'] == 0:
        await update.message.reply_text(f"No results found for query: {query}")
        return
    
    for result in results['matches'][:5]:  # Show top 5 results
        ip_str = result['ip_str']
        await update.message.reply_text(f"IP: {ip_str}\nData: {result['data']}\n")

# Pyshark Packet Capture Function
async def capture_packets(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    interface = ' '.join(context.args) or 'eth0'
    capture = pyshark.LiveCapture(interface=interface)
    
    await update.message.reply_text(f"Starting packet capture on interface {interface}...")
    
    packets = []
    for packet in capture.sniff_continuously(packet_count=10):
        packets.append(packet)
        await update.message.reply_text(str(packet))
    
    await update.message.reply_text(f"Captured {len(packets)} packets.")

# Start Command Function
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Hello! I am your Cybersecurity bot.\n"
        "You can use the following commands:\n"
        "/scan [target] - Run Nmap scan\n"
        "/nuclei [target] - Run Nuclei scan\n"
        "/shodan [query] - Search on Shodan\n"
        "/capture [interface] - Capture packets with Pyshark\n"
    )

# Main Function
async def main() -> None:
    application = Application.builder().token("YOUR_BOT_API_TOKEN").build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("scan", nmap_scan))
    application.add_handler(CommandHandler("nuclei", nuclei_scan))
    application.add_handler(CommandHandler("shodan", shodan_search))
    application.add_handler(CommandHandler("capture", capture_packets))

    await application.run_polling()

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
